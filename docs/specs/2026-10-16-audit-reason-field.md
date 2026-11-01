# Audit `reason` field — design (2026-10-16)

- **Status:** accepted by the owner 2026-10-16. Implemented (plan Tasks 1-8); Task 9 E2E pending.
- **Owner decisions (2026-10-16):** add a `reason` field to the audit record (chosen over
  keeping the reason in `operation` and over moving it to the `zs-diag` log). The reader is an
  admin, and the main use is audit review.
- **Order:** after per-path injection scope (ADR-0027, done 2026-10-16).
- **Plan:** the implementation plan (not published)
- **Decision record:** ADR-0032, written by the plan's docs task.

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

## 1. Problem

The audit record has no field for why a request was denied. Some deny paths put the reason
text in `operation`. The other paths record no reason.

| Deny path | File and line | `operation` today | Reason today |
|---|---|---|---|
| CONNECT, `classify` denies the tunnel (host-wide binding) | `crates/zs-mitm/src/proxy.rs:590` | the reason text | in `operation` |
| CONNECT, `authorize_request` deny after the allow `connect` record (line 653) | `proxy.rs:667` | the reason text | in `operation` |
| Absolute-form (plain proxy) request, `classify` deny | `proxy.rs:798` | the reason text | in `operation` |
| Path-scope refusal (`ScopeDecision::Refuse`) via `refuse()` | `proxy.rs:879`, `1143` | the method | none (rule code only in `zs-diag`) |
| Origin refusal (`origin_refusal`) via `refuse()` | `proxy.rs:1122` | the method | none (rule code only in `zs-diag`) |
| Authorize, materialize or inject failure | `proxy.rs:930`, `1208` | the method | none (stage only in `zs-diag`) |
| L3 `connect` materialize failure (PostgreSQL, MySQL, MongoDB) | `apps/zs/src/run.rs:96` (`l3_materialize`) | `connect` | none (`Denied` reason dropped) |
| MySQL client `COM_CHANGE_USER` refusal | `crates/zs-proto-mysql/src/lib.rs:807` | `change_user` | none |
| MongoDB client authentication refusal | `crates/zs-proto-mongo/src/lib.rs:997` | `authenticate` | none |

The effects:
- An admin cannot filter or count by `operation`. On 3 paths it holds free text.
- An admin cannot tell from the record alone why most denies happened.
- The 2026-10-16 acme discrimination run read H6 as CONFIRMED, although the revoke worked,
  because the harness read the deny text in `operation`.

The project state file (not published) says request-time denies record the method. That is correct for the real
per-request paths (`proxy.rs:930`, `1208`). It does not mention `proxy.rs:667`, which runs at
CONNECT time in `handle_tunnel`, before any inner request exists. The plan's docs task adds it.

## 2. Goal, non-goals, anti-goals

**Goal.** Every deny record says why it was denied, in its own field. The field is part of the
hash chain and goes everywhere the record goes. `operation` always names the action.

**Non-goals.**
- A reason on allow or passthrough records. One example is the grant id that allowed a
  request. This is a possible follow-up (§7).
- Filtering or searching by reason in the dashboard or the export query.
- The "audit host with userinfo" open item.
- A change to `zs-diag` events. They keep their codes.
- A change to the `zs:` stdout and stderr lines.

**Anti-goals** (the work fails if any of these happen, even if the tests pass):
- A credential value, an upstream message, or workload data other than the destination host
  and port reaches `reason`. Hard rule 4 applies. The host and port are already in
  `resource`.
- A journal written before this change no longer opens or verifies.
- A deny path stops writing its audit record, or a failed audit write stops failing closed.
- `operation` holds reason text on any path.

## 3. Decisions

**Record shape.** `AuditRequest` and `AuditRecord` in `zs-audit` get
`reason: Option<String>`. `None` means "no reason". The journal JSON leaves the key out when
the value is `None` (`skip_serializing_if`), and a missing key reads as `None`
(`serde(default)`). So allow records look the same as today, and old lines still parse.

**Hash chain.** When `reason` is `None`, the hash input does not change, so existing journals
verify unchanged. When `reason` is `Some(text)`, `hash_record` appends `0x00`, the text
bytes and a final `0x00` after the decision bytes. A hash input without a reason ends with
the last byte of a decision word (`allow`, `deny`, `passthrough`), never with `0x00`, so a
record with a reason never hashes the same as a record without one. This does not depend on
the other fields: `operation` can hold a NUL byte, because the proxy takes the HTTP method
from the request line as the client sent it (`proxy.rs:184`). `zs-audit` replaces each NUL
byte in a reason with U+FFFD before it hashes and writes the record, so the reason is always
the last NUL-delimited segment. An empty string is not a valid reason: the journal stores it
as `None`.

Amended 2026-10-16 during planning: the first draft appended no final `0x00` and said that
no field holds a NUL byte. `operation` can.

**Downgrade is one-way.** An older agent ignores the `reason` key, computes a different
hash, and reports `ChainBroken` for the first record with a reason. `zs run` then refuses to
start in that project until `.zs-audit/audit.jsonl` is moved. This is accepted. No format
version is added. ADR-0032 says so.

**`operation` values.** On every deny path, `operation` is the HTTP method, `connect` for a
deny at CONNECT time (`proxy.rs:590` and `667`), or the fixed protocol operation (`connect`, `change_user`,
`authenticate`). The `audit()` helper in `proxy.rs` gets separate `operation` and `reason`
parameters. The `reason.unwrap_or("connect")` fallback goes away.

**Reason text per path.**

| Deny path | `reason` |
|---|---|
| `classify` deny (CONNECT and absolute-form) | the `Flow::Deny` reason text, unchanged |
| `authorize_request` deny (`proxy.rs:667`) | the reason text that it returns today |
| Path-scope and origin refusal | the refusal rule code that `zs-diag` already records (`Refusal::code`) |
| Identity, authorize or inject failure (`proxy.rs:930`, `1208`) | the `Denied` reason |
| Grant check inside `AgentHandler::materialize` (`apps/zs/src/lib.rs:685`; HTTPS and L3) | the verifier's reason text, as `classify` uses it |
| Credential provider failure inside `AgentHandler::materialize` (`lib.rs:690`; HTTPS and L3) | the fixed text `materialize failed` |
| Panic in the inject closure (`proxy.rs:1208`) | the fixed text `panic` |
| MySQL `change_user`, MongoDB `authenticate` | a fixed text from the protocol crate. `AuditRefusal` takes the operation and the reason, both `&'static str` |

`zs_protocol::Denied` gets an audit-only reason. `AgentHandler::materialize` sets it to
`materialize failed` for a credential provider error. The `Denied` text that the client sees
(for example the PostgreSQL `ErrorResponse`) does not change. A grant check failure inside
`materialize` keeps its verifier text in both, because a path-scoped binding checks its grant
there. Amended 2026-10-16 during planning: the first draft used `materialize failed` for the
whole materialize stage, which hid a revoked grant on a path-scoped binding.

Credential provider errors are not passed through. `MaterializationError` text can hold an upstream
message: a `reqwest` error with its URL, a `serde` error on a vault or exchange reply, or the
PostgreSQL server's reply to `CREATE ROLE` (`crates/zs-materializer/src/lib.rs:90`, `100`,
`150`, `160`, `333`). Only `FileStore` and `UnconfiguredExchange` are wired into `zs run`
today, but `reason` goes into the hash chain and the central database, so the rule must not
depend on the wiring.

**Central path.** `zs_wire::AuditIngestRecord` gets `reason: Option<String>` with
`serde(default)`. `zs-wire` does not use `deny_unknown_fields`, so:
- an old agent sends records without `reason`, and the new control plane stores `NULL`;
- a new agent sends `reason` to an old control plane, which ignores it.

Either side can be upgraded first. The migration (`apps/control/migrations/0001_initial.sql`,
idempotent statements) adds
`ALTER TABLE audit_records ADD COLUMN IF NOT EXISTS reason TEXT` (nullable, no default). The
store writes and reads the column. The sqlx offline query data is regenerated.

**Export and dashboard.** The NDJSON export carries `reason` through `AuditIngestRecord`. The
dashboard audit browser adds a "Reason" column after "Decision". The value is HTML-escaped,
as maud escapes every other column.

## 4. Success criteria

1. Every deny path in §1 writes a record with a non-empty `reason`. Its `operation` is a
   method, `connect`, or the fixed protocol operation. One test per path proves it.
2. A journal fixture written by the current code (no `reason` key) opens and verifies with
   the new code.
3. Changing the `reason` text of one record in a journal makes `Journal::open` return
   `ChainBroken` for that record.
4. A record with a `reason` goes from the agent through `/wire/audit` into `audit_records`.
   It appears in `/export/audit` and in the dashboard audit table. A record without one is
   stored as `NULL`.
5. `cargo test --workspace`, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
   and `cargo deny check` pass. The CI `db-real` job passes.
6. The acme harness H6 check counts `deny` records for the resource after the revoke whose
   `operation` is `POST` or `connect`. It does not match on `reason` text. A rerun of the
   full run gives exit 0 and H6 REFUTED. A rerun of the discrimination run (host-wide
   binding) gives exit 50, S6 FAIL and H6 REFUTED.
7. `crates/zs-audit/tests/record_shape.rs` is updated on purpose to the new shape.

## 5. Constraints

- Hard rule 3: an audit write failure still denies, on every path.
- Hard rule 4: `reason` holds only text that the agent makes. It may name the destination
  host and port, the subject, a grant id or a rule code. It never holds an upstream error
  message, a workload header, a path or a body.
- No new dependency.
- The acme and globex harnesses are test beds. Their changes are not deliverables.

## 6. Left to the builder

- How each deny path gets its reason to `audit()`, and the helper signatures.
- The fixed reason texts for `change_user` and `authenticate`.
- Test names, fixtures, and which existing tests are updated to the new `operation` values.
- How the acme harness `audit.cjs` and `verdicts.cjs` read the new field.

## 7. Possible follow-ups (not scheduled)

- A reason on allow records, for example the grant id that allowed the request.
- A reason filter in the dashboard and the export query.
