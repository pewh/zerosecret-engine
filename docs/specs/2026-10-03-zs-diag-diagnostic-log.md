# `zs-diag` diagnostic log — design (2026-10-03)

- **Status:** draft for owner review. No code exists.
- **Owner decisions (2026-10-03):** content is events and metadata only; one file per run,
  always on; a write failure never blocks traffic; a separate crate.
- **Order:** after per-path injection scope, before `zs-proto-mysql`.
- **Plan:** the implementation plan (not published)
- **Decision record:** ADR-0028, written by the plan's docs task.

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

## 1. Problem

When `zs run` fails, the evidence is not enough to find the cause quickly.

| Component | What it records today |
|---|---|
| `zs-proto-postgres` | Nothing. `serve_with` drops every connection error: `let _ = handle_connection(…)` (`lib.rs:1014`) |
| `zs-mitm` | Three fixed stderr lines: `connection ended: <error>`, `relay error`, `upstream write error` |
| `run.rs` | 34 `zs:` lines on stdout and stderr, mixed with the workload's own output |
| Audit journal | One decision record per connection or request. No reason, no timing, no failure kind |

The owner wants one file per run that a person or an LLM can read to find a bug. That file
must not leak a credential (hard rule 4) or the workload's data (PRODUCT §3: not a traffic
inspection product).

## 2. Goal, non-goals, success criteria

**Goal.** Every `zs run` writes one JSON Lines file. The file records each decision, state
change and failure in the agent, with a fixed reason code. The file is safe to give to an LLM.

**Non-goals.**
- Traffic capture: no bodies, no SQL, no header values.
- Shipping the file to the control plane.
- A general logging facade: no `log!`/`tracing` macros, no free-form messages.
- A change to the audit journal or to its fail-closed rule.
- A change to the existing `zs:` stdout and stderr lines. The acme harness parses them.

**Success criteria.**
1. A PostgreSQL handshake that fails upstream leaves an event with the failure kind and the
   SQLSTATE.
2. An HTTP request that the agent refuses leaves an event with the rule that fired.
3. After positive traffic, the log contains no credential value and no request path.
4. A full disk or an unwritable directory does not stop or slow traffic.
5. Added p95 latency stays within the budget (`budget_latency`).

## 3. Placement: a new crate `zs-diag`

- `zs-proto-postgres` does not depend on `zs-audit` today. A log inside `zs-audit` would make
  every protocol crate depend on the security journal.
- The journal fails closed and the log is best-effort. Separate crates keep the two failure
  rules apart.
- The name is `zs-diag`, not `zs-logger`, because the crate takes typed events, not messages.
- Dependencies: `serde_json` only. It depends on no `zs-*` crate. It goes first in
  `dependency_rule.rs` `MAP`.
- ARCHITECTURE §2 gets the line `zs-diag  per-run diagnostic events, typed, never a credential`.

## 4. The file

| Item | Rule |
|---|---|
| Path | `<D>/run-<start epoch ms>-<pid>.jsonl`, where `<D>` is `.zs-log` next to the audit directory: `<parent of the --audit directory>/.zs-log`. For the default `--audit .zs-audit/audit.jsonl`, `<D>` is `./.zs-log`. For `--audit <tmp>/<dir>/audit.jsonl`, `<D>` is `<tmp>/.zs-log`. For `--audit <tmp>/audit.jsonl`, `<D>` is in the parent of `<tmp>`, not in `<tmp>`. A test that must keep the log in its temporary directory uses an audit subdirectory or `--log`. `--log <path>` sets an exact file instead |
| Permissions | Directory 0700, file 0600 (Unix). Windows: default ACL of the user's directory |
| Retention | At start, keep the 10 newest `run-*.jsonl` files in `<D>`, this run included. "Newest" is the name order. The file of this run is never deleted, also when a clock skew puts older names after it. Delete only files that match that pattern. No pruning with `--log`. `--log` appends, and the cap is per run |
| Cap | 50 MiB. At the cap, write one `log_capped` event and stop writing. The start of a run holds its context, so the start is kept |
| Announcement | One stderr line at start: `zs: diagnostic log <path>` |
| Failure | Cannot create or write: one stderr line `zs: diagnostic log unavailable: <io error kind>`. After the first write or flush error, the writer stops. Traffic continues |

## 5. Event shape

One JSON object per line:

```json
{"ts_ms":1791000000123,"run":"1791000000000-4242","seq":17,"level":"warn","component":"postgres","event":"upstream_auth_failed","conn":5,"resource":"orders-db","dest":"db.internal:5432","audit_seq":31,"fields":{"sqlstate":"28P01"},"error":{"kind":"refused","text":"password authentication failed for user \"app\""}}
```

| Key | Type | Present |
|---|---|---|
| `ts_ms` | u64, epoch ms | always |
| `run` | `<start epoch ms>-<pid>` | always |
| `seq` | u64, per file, from 1 | always |
| `level` | `info`, `warn` or `error` | always |
| `component` | `agent`, `grant`, `proxy`, `postgres`, `mysql` | always |
| `event` | snake_case code from §6 | always |
| `conn` | u64, unique per run across components | connection events |
| `req` | u64, from 1 within a connection | request events |
| `resource` | token | when known |
| `dest` | `host:port` token. The host has only `A–Z a–z 0–9 . - : [ ]`. Other host text, or a request target with userinfo (`@`), gives `"invalid"` | when known |
| `audit_seq` | u64, the audit record written for this decision | when a record was written |
| `fields` | object of typed values (§7) | when not empty |
| `error` | `{"kind": code, "text": server text}`; `text` is optional | failures |

## 6. Event catalogue

| Component | Event | Level | Fields |
|---|---|---|---|
| agent | `run_started` | info | `version`, `os`, `listen`, `bindings` (count), `subject_source`; one `binding` event per binding follows |
| agent | `run_refused` | error | `stage`: the start step that stopped the run (`args`, `config`, `signing_keys`, `subject`, `workload`, `audit`, `ca`, `runtime`, `control`, `revocations`, `listen`, `proxy_bind`, `postgres_upstream`, `postgres_bind`, `child_spawn`) |
| agent | `binding` | info | `resource`, `host`, `protocol`, `scheme`, `operations`, `scope_entries` (a count; the entries are not logged, so no path-like text is in the file), `scoped` (bool: the binding has `paths`), `upstream_override` (bool), `upstream_plaintext` (bool) |
| agent | `listener_bound` | info | `kind` (`proxy`, `postgres`, `mysql`), `addr` |
| agent | `child_spawned` | info | `program` (basename of argv[0] only), `pid` |
| agent | `child_exited` | info | `code` or `signal` |
| agent | `run_ended` | info | `dropped` (events lost to a full queue) |
| grant | `grant_minted`, `grant_renewed` | info | `grant_id`, `operations`, `expires_in_s` |
| grant | `grant_failed`, `renewal_failed` | warn | `error.kind` |
| grant | `revocations_applied` | info | `count` |
| grant | `refresh_failed` | warn | `error.kind` |
| proxy | `conn_accepted` | info | `form` (`connect`, `absolute`) |
| proxy | `classified` | info | `flow` (`intercept`, `passthrough`, `deny`), `audit_seq`; the deny reason text stays in the audit record |
| proxy | `client_tls_failed` | warn | `error.kind` |
| proxy | `request_decided` | info | `method`, `scope` (`inject`, `forward`, `refuse`), `rule` (refusal code), `decision` (`allow`, `deny`, `passthrough`), `deny_kind` (`identity`, `authorize`, `materialize`, `inject`, `panic`, `audit_unavailable`), `audit_seq` |
| proxy | `upstream_failed` | warn | `stage` (`connect`, `tls`, `write`, `relay`), `error.kind` |
| proxy | `response_relayed` | info | `status`, `bytes`, `ms` |
| proxy | `conn_closed` | info or warn | `ms`, `result` (`ok`, `error`), `error.kind` (I/O kind or a fixed framing code: `unparseable`, `unsupported_form`, `conflicting_length`, `body_too_large`, …) |
| postgres | `conn_accepted` | info | — |
| postgres | `materialized` | info or warn | `decision`, `deny_kind` |
| postgres | `upstream_connected` / `upstream_failed` | info / warn | `stage`, `error.kind` |
| postgres | `upstream_auth_ok` | info | `mechanism` |
| postgres | `upstream_auth_failed` | warn | `sqlstate`, `error.kind`, `error.text` |
| postgres | `conn_closed` | info | `bytes_up`, `bytes_down`, `ms`, `closed_by` (`client` or `upstream`: the side that closed first). Written after every relay. A relay error also writes `conn_failed` with `stage` `relay` |
| postgres | `conn_failed` | warn | `stage` (`startup`, `cancel`, `connect`, `write`, `auth`, `ready`, `relay`), `error.kind`; replaces the dropped error at `lib.rs:1014`. `ready` is the write of the handshake end to the client |

Refusal rule codes for `request_decided.rule`: `not_origin_form`, `fragment`, `forbidden_byte`,
`bad_escape`, `forbidden_escape`, `dot_segment`, `empty_segment`, `host_missing`,
`host_repeated`, `host_mismatch`. They come from `target_refusal(target) -> Option<Refusal>` and
from the tunnel origin check (`origin_refusal`). They do not come from `ScopeDecision`, which
does not change. Both functions are next to the per-path code. When `target_refusal` finds no
rule, the code is `unknown`.

## 7. What a field can hold, and how the rule is enforced

`zs-diag` has no API that takes a free-form `String` from the network.

| Value type | Constructor | Holds |
|---|---|---|
| `Code` | `&'static str` | Reason codes, event names, enum names |
| `Num` | `u64` only | Counts, bytes, ms, status, pid, errno |
| `Flag` | `bool` | Flags |
| `Token` | `Token::new(&str) -> Option<Token>` | Resource, host, host:port, grant ID, method, plugin, version, scope entry, SQLSTATE. Allowed bytes: `A–Z a–z 0–9 . _ - : @ [ ] /`, 1–128 bytes. No space, `?`, `%`, `=`, `&`, `#`, `;`, `\`, quote |
| `ServerText` | `ServerText::new(text: &str, secret: &[u8]) -> Option<ServerText>` | Server error text during a handshake only. Control bytes removed, cut to 200 chars. `None` when it contains the secret bytes |

Rules a reviewer checks:
- A request path, a query string, a header value, SQL text, a body, argv after argv[0], or an
  environment value never becomes a `Token` or a `ServerText`.
- `ServerText` is built only where the credential is in scope, so the containment check is real.
- Subject (a person's identity) is not logged. `run_started` logs `subject_source` (`session` or
  `env`) instead. The audit journal, joined by `audit_seq`, keeps the subject locally.

Tests:
- Absence: positive traffic through HTTP and PostgreSQL with a synthetic credential and a
  distinctive path segment. Then the log contains neither.
- `Token::new` refuses every forbidden byte; `ServerText::new` refuses a text that holds the secret.
- Schema: every line parses as JSON and has the keys from §5.

## 8. Writer

- `DiagLog` is a cheap clone handle. `DiagLog::disabled()` is a no-op handle for tests and for
  library callers.
- `emit` puts the time on the typed event on the caller's thread and does `try_send` on a
  bounded `std::sync::mpsc::sync_channel(4096)`. A full queue increments `dropped`. It never
  blocks.
- One writer thread builds each JSON line, appends it, and tracks the byte count for the cap.
  It does not `fsync`. On the first write or flush error, it writes the one stderr line from §4
  and stops writing.
- `DiagLog::close` sends a stop message, joins the thread, and writes `run_ended`.
- `conn` IDs come from one `AtomicU64` in the handle, so IDs are unique across components.

## 9. Integration

| Where | Change |
|---|---|
| `apps/zs/src/main.rs` | `--log <path>` flag; usage text |
| `apps/zs/src/run.rs` | Open the log in `prepare`; emit agent and grant events; pass the handle to the proxy and to each L3 listener; close at the end of `run` |
| `crates/zs-mitm/src/proxy.rs` | `ProxyServer::with_diag(DiagLog)`; events from §6; the three stderr lines stay |
| `crates/zs-mitm/src/scope.rs` | `Refusal` with the codes from §6, and `target_refusal(target) -> Option<Refusal>`. `ScopeDecision` does not change, so the per-path tests stay as they are |
| `crates/zs-proto-postgres/src/lib.rs` | `PostgresListener::with_diag(DiagLog)`; events from §6; `serve_with` logs the error it drops today |
| `crates/zs-audit/src/lib.rs` | `Journal::append_seq` returns the written `seq`, so events can carry `audit_seq`. `append` is unchanged |
| `.gitignore` | `/.zs-log/` |

`with_diag` builder methods keep every existing `bind` call and test unchanged.

## 10. SECURITY changes

| Section | Change |
|---|---|
| §4 Credential handling rules | Add: the diagnostic log follows rule 4. It holds typed values only (§7) |
| §5 Audit | Add: the audit journal is the security record and fails closed. The diagnostic log is a best-effort debugging record. It carries no authority, and it can be lost |
| §7 | Row 20: "Diagnostic log unavailable or full → traffic continues; one stderr warning; never a credential in it (ADR-0028)". Test `row_20_a_diagnostic_log_failure_never_blocks_traffic` |

## 11. Risks

- **Over-collection in later code.** A future change can put a path into a `Token`, because a
  path can be valid `Token` text. The absence test with a distinctive path segment and code
  review guard this.
- **Lost events.** A full queue drops events. `run_ended.dropped` makes the loss visible.
- **Disk use.** 10 runs × 50 MiB is at most 500 MiB per directory.
- **No `audit_seq` on PostgreSQL events.** The PostgreSQL audit record is written inside the
  `Materialize` closure in `run.rs`, which has no connection ID. A reader joins PostgreSQL events
  to the journal by `ts_ms` and `resource`.
- **Internal names.** Hostnames and resource names go to the LLM with the file. The owner
  accepted this for debugging (2026-10-03).
- **No signal handling.** `zs run` handles no signals. Ctrl-C, SIGTERM, SIGKILL or OOM leave no
  `child_exited` or `run_ended`. A reader treats a missing `run_ended` as "the run was killed",
  and skips a last line that does not parse.
