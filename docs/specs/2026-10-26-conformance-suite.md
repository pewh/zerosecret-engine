# Protocol conformance suite

Status: **approved by the owner 2026-10-26; built 2026-10-27; section 6.2 amended 2026-10-27 on the owner's instruction for SV-06**. Date: 2026-10-26.
Plan: the implementation plan (not published).
Evidence: the sandbox-runtime-parent spike notes (not published) (the acceptance shape across five protocols),
`apps/zs/tests/{postgres_real,postgres_l3,mysql_l3,mongo_l3}.rs` (the seed cases).

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

## 1. Why

ZeroSecret's moat, as the owner settled it on 2026-10-26, is open core: the engine is
open-sourced and the defensible part is the conformance suite plus auditor-grade `zs-verify`
evidence. A proxy that sits between a real client and a real database either speaks the wire
protocol correctly or silently corrupts sessions. Today nothing proves which.

What exists is close but not it. `postgres_real.rs` proves a real `psql` reaches a
password-protected server with no password. `mongo_l3.rs` proves a real driver authenticates over
SCRAM-SHA-256. The sandbox-runtime spike proves all five protocols at once with negative controls.
Each of those answers "does the happy path work". None answers "does this proxy speak the
protocol", which is a different and larger question: extended-protocol message flow, COPY streams,
SQLSTATE fidelity, cancel requests, result metadata, warning counts, legacy framing, nesting
limits, and signature vectors.

Those gaps are where a proxy breaks a workload in production without failing a single existing
test.

## 2. Goals

1. For each of PostgreSQL, MySQL, MongoDB and AWS SigV4, prove with real third-party clients that
   the proxy under test speaks the protocol, not merely that a query returns a row.
2. Every positive case carries two negative controls: wrong credential and wrong upstream TLS
   identity. A case that passes because nothing was checked is a defect of the suite.
3. The suite is runnable against **any** implementation through a shell adapter, with no
   ZeroSecret-specific code in any test body.
4. The suite runs in ZeroSecret CI on every push, as a real gate.
5. Evidence is a command and its output. A capability matrix is produced on every run and is
   readable by someone who did not write it.

## 3. Non-goals

- Performance, throughput or latency. `budget_latency` and `budget_footprint` own that.
- Fuzzing or adversarial protocol abuse. This suite checks conformance, not robustness.
- Redis, MSSQL, gRPC or HTTP/2. Out of scope until a workload needs one.
- A public repository, now. See section 5, decision D1.
- Replacing `fail_closed_matrix.rs`. Fail-closed policy is a ZeroSecret property; this suite tests
  wire behaviour, which is vendor-neutral. Neither absorbs the other.
- Audit-journal assertions. What a proxy records is its own concern; another implementation may
  record nothing and still be conformant. The only exception is the leak scan in section 6.2.

## 4. Anti-goals

Things that would make this a failure even if every test were green.

- **A suite only ZeroSecret can pass.** If a case asserts ZeroSecret's exact error text where the
  protocol permits any error, it is a branding test, not a conformance test. Error-text assertions
  belong only where the protocol fixes the value, for example a SQLSTATE or a MySQL error number.
- **A suite that needs ZeroSecret to run.** A `zs_*` crate in `[dependencies]` kills the
  extraction story in section 6.4.
- **Green through skipping.** A case whose fixture is absent must report `SKIPPED` loudly in the
  matrix and in the exit summary, never count as a pass.
- **A leaked fixture password.** Printing one is a failure of the run regardless of the result.

## 5. Owner decisions

Settled with the owner on 2026-10-26, during brainstorming.

- **D1 — In-workspace Rust crate, extractable later.** `crates/zs-conformance/`, run in ZeroSecret
  CI. The first runner is ZeroSecret itself, so a second repository and a second CI setup are not
  paid for yet. The extraction seam is a hard rule, not an intention: section 6.4.
- **D2 — Known gaps are hard failures.** Cases the implementation refuses today are red, and CI is
  red with them. There is no "declared unsupported" escape. Section 10 lists which cases this makes
  red on day one and what closes each.
- **D3 — All four protocols, full scope, in one pass.** The plan delivers the whole suite before
  review rather than one protocol as a template.
- **D4 — Setup is a shell adapter per implementation.** The suite never launches a proxy itself.
  Section 6.2 fixes the contract.

## 6. Shape

### 6.1 Layout

```
crates/zs-conformance/
  Cargo.toml
  conformance.toml            default config: the ZeroSecret adapter
  adapters/zerosecret.sh      wraps `zs run`
  vectors/aws-sig-v4-test-suite/   vendored official vectors, provenance in VECTORS.md
  src/
    lib.rs                    case registry, runner, report
    adapter.rs                the D4 contract
    config.rs
    report.rs                 JSON + markdown capability matrix
    cases/{postgres,mysql,mongodb,sigv4}.rs
    main.rs                   `zs-conformance run --config <path>`
  tests/conformance.rs        runs the registry against conformance.toml
```

One case list, two drivers. `cargo test -p zs-conformance` is the CI gate; `zs-conformance run
--config other.toml` is how a third party points it at their own proxy. Neither duplicates a case.

### 6.2 The adapter contract

The suite calls one executable, named in config. Two subcommands, both line-oriented so a shell
script can implement them.

```
<adapter> setup --protocol <postgres|mysql|mongodb|http>
                --case <CASE-ID>
                --upstream-host <host> --upstream-port <port>
                --credential-file <path>
                [--upstream-ca <path>] [--upstream-tls <default|plaintext|ca-sha256:HEX|pin-sha256:HEX>]
                [--operations <csv>] [--auth-scheme <name>] [--access-key-id <id>]
```

On success it prints one line of JSON to stdout and exits 0:

```json
{"handle":"opaque","endpoint":"127.0.0.1:54321","env":{"PGHOST":"127.0.0.1","PGPORT":"54321"}}
```

```
<adapter> teardown --handle <opaque>
```

One management subcommand, added 2026-10-27 so SV-06 stays vendor-neutral. The suite calls
it only for the presign case.

```
<adapter> presign --handle <opaque> --url <absolute-url> --method <GET|PUT|...> [--expires <seconds>]
```

On success it prints one line of JSON to stdout and exits 0:

```json
{"url":"https://upstream.example/bucket/key?X-Amz-Signature=..."}
```

`--expires` defaults to 600. The suite asks for a value above the implementation's cap and
expects the adapter to fail, then asks for one inside the cap.

Rules the suite enforces:

- `setup` must not print the credential. The suite scans adapter stdout and stderr for the
  credential bytes and fails the case if found.
- The suite reads the credential value only to write `--credential-file` and to run the leak scan.
  It never passes it to a client.
- A non-zero `setup` exit is a case failure with the adapter's stderr attached, not a skip.
- `teardown` runs even when the case fails, and its failure is reported separately from the case.

`adapters/zerosecret.sh` writes a `zs-policy.json` and a signed-grant-free local policy into a
temporary home and runs `zs run` in the background, then prints the bound listener. It is the only
file in the crate that knows ZeroSecret exists.

### 6.3 Clients

Real third-party clients, as subprocesses, matching what `postgres_real.rs` and `mongo_l3.rs`
already do:

| Protocol | Client | Used for |
|---|---|---|
| PostgreSQL | `psql` | simple query, startup options, COPY, SQLSTATE, cancel |
| PostgreSQL | `tokio-postgres` (dev-dependency) | extended protocol, binary COPY |
| MySQL | `mysql` CLI | every case |
| MongoDB | `mongosh` | every case |
| SigV4 | `curl` + the vendored vectors | re-signing, encoding, port |

`tokio-postgres` is a call made here, not an owner decision: `psql` only speaks the simple query
protocol, and the extended protocol is in scope. It is a third-party client, not ZeroSecret code,
so the vendor-neutral claim holds. See section 11.

### 6.4 What the suite provides for itself

Three pieces the cases need that neither the fixture nor the adapter supplies. All three live in
the crate and none of them knows ZeroSecret exists.

- **Roles.** The suite provisions its own fixture roles once per run, using the fixture
  administrator credential read from `docker-compose.yml`: a PostgreSQL role with a known password,
  the MySQL `zs_sha2` and `zs_native` users (already in `fixtures/mysql/init.sql`), and the MongoDB
  users from `tools/mongo-test-setup.sh`. Provisioning is idempotent and its SQL is never logged,
  because it contains the password. MY-02 needs `FLUSH PRIVILEGES` on the fixture, which this same
  administrator connection performs.
- **A fake HTTP upstream.** SV-01 to SV-06 need an upstream that reports what it received. The
  crate binds one on loopback: it echoes the `Authorization` header's credential scope and the
  signed headers, and it recomputes the SigV4 signature from the vendored vectors' secret so SV-01
  verifies a signature rather than only a key id. The sandbox-runtime spike's check 16 only proved
  the key id was swapped; this does better.
- **A throwaway wrong CA.** The `-wrongca` control needs a valid but unrelated CA. The suite
  generates one per run into `target/conformance/wrong-ca/` rather than reusing the ZeroSecret
  control-plane CA, which would be an implementation-specific path.

### 6.5 The extraction seam

Four rules, each with a test in `tests/conformance.rs` so a later change cannot quietly break
them:

1. `crates/zs-conformance/Cargo.toml` has no `zs-*` or `control` entry in `[dependencies]` or
   `[dev-dependencies]`. Asserted by parsing the manifest.
2. No file under `src/cases/` contains the string `zs ` as a command, `zs-policy`, or `zerosecret`.
   Asserted by reading the sources at test time.
3. The crate builds and its case registry enumerates with `conformance.toml` absent.
4. `adapters/zerosecret.sh` is the only path under the crate that matches `zs ` or `zerosecret`,
   outside `conformance.toml` and the README.

With those held, extraction is `git mv` plus a CI file.

## 7. Case catalogue

Every case ID below is a test name. Each positive case P runs twice more: `P-wrongpass` with a
corrupted credential file and `P-wrongca` with the control-plane CA substituted for the upstream
CA. A case whose upstream binding is plaintext has no TLS identity to substitute, so it carries
`P-wrongpass` only; that is the SigV4 family. Both controls must fail with the client surfacing an authentication or TLS error, and the
query string or payload must not appear in the upstream's log.

### PostgreSQL

| ID | Case |
|---|---|
| PG-01 | SCRAM-SHA-256 against a credential-free client; a row comes back |
| PG-02 | Startup packet: `application_name`, `client_encoding` and a `-c` option reach the server and are readable via `current_setting` |
| PG-03 | `SSLRequest` and startTLS to the upstream, CA pinned with `ca-sha256`, verified by the server log |
| PG-04 | Extended protocol: Parse/Bind/Describe/Execute with a typed parameter and a prepared statement reused twice |
| PG-05 | `COPY … FROM STDIN` streams 10,000 rows in and they are all present |
| PG-06 | `COPY … TO STDOUT` streams them back byte-identical |
| PG-07 | SQLSTATE passthrough: `23505` on a unique violation and `42P01` on a missing relation reach the client unchanged |
| PG-08 | `CancelRequest`: a long `pg_sleep` is cancelled and the client sees `57014` |

### MySQL

| ID | Case |
|---|---|
| MY-01 | `caching_sha2_password` fast path: a second connection after a successful one uses the cached scramble |
| MY-02 | `caching_sha2_password` full auth: after `FLUSH PRIVILEGES`, the first connection completes the full exchange |
| MY-03 | `mysql_native_password` against `zs_native` |
| MY-04 | Upstream TLS verified with the fixture CA pinned |
| MY-05 | Result metadata: column name, type and charset of a `VARCHAR`, an `INT` and a `JSON` column survive the proxy |
| MY-06 | Warnings preserved: a truncating insert reports a non-zero warning count and `SHOW WARNINGS` returns the text |
| MY-07 | Session reset: `COM_RESET_CONNECTION` clears a user variable and the session continues |
| MY-08 | Error 3141 (invalid JSON text) reaches the client with its number and SQLSTATE `22032` |

### MongoDB

| ID | Case |
|---|---|
| MG-01 | SCRAM-SHA-256 as `zs_sha256` in `zsdb` |
| MG-02 | SCRAM-SHA-1 as `zs_sha1` in `admin` |
| MG-03 | `OP_MSG` framing: an insert and a find round-trip, including a payload type 1 section |
| MG-04 | `OP_QUERY` legacy framing: a `hello` with no `$db` is answered |
| MG-05 | Speculative authenticate inside `hello` completes without a second round trip |
| MG-06 | Nesting depth: a BSON document nested past the server limit is refused with an error, and the proxy stays up |
| MG-07 | `directConnection=true` reaches the single node without topology discovery |

### AWS SigV4

| ID | Case |
|---|---|
| SV-01 | Every official `aws-sig-v4-test-suite` vector: canonical request, string to sign and signature match |
| SV-02 | Path encoding: a key containing `(`, `)`, `!` and a double slash is signed as AWS encodes it |
| SV-03 | The signed `Host` carries the port when the forwarded request has a non-default one |
| SV-04 | Re-signing per ADR-0035: a request signed with a fake key arrives upstream signed with the real one; an unsigned request is relayed unsigned |
| SV-05 | `STREAMING-UNSIGNED-PAYLOAD-TRAILER` body is signed and reaches the upstream intact |
| SV-06 | A presign request above the expiry cap is refused, and one inside it is issued and verifies |

40 positives, 80 controls. SV-01 is one case over many vectors; its report line carries the vector
count.

## 8. Fixtures

All in `docker-compose.yml` behind profiles, verified 2026-10-26.

| Fixture | Container | Host port | Profile |
|---|---|---|---|
| PostgreSQL | `zerosecret-postgres-1` | 5434 | none |
| PostgreSQL TLS | `zerosecret-postgres-tls-1` | 5435 | `pgtls` |
| MySQL | `zerosecret-mysql-1` | 3307 | `mysql` |
| MongoDB | `zerosecret-mongo-1` | 27018 | `mongo` |

Certificates come from `tools/db-test-certs.sh` into `target/db-test-certs/`; the CA file is
`ca.pem`, not `ca.crt`. `zs ca-sha256 target/db-test-certs/ca.pem` gives the pin. MongoDB needs
`tools/mongo-test-setup.sh`, which is idempotent and creates `zs_sha256` in `zsdb` and `zs_sha1`
in `admin`. `fixtures/mysql/init.sql` creates `zs_sha2` and `zs_native`.

The suite does not start fixtures. A fixture that is not listening makes its cases `SKIPPED` with
the compose command to start it printed once, and the run exits non-zero if any case skipped,
unless `--allow-skips` is passed.

**Fixture passwords are never printed.** The suite reads them from the environment or from
`docker-compose.yml`, writes them only to the adapter's `--credential-file`, and redacts them to
`[REDACTED]` in every report, log line and error message. A redaction test asserts this over the
whole report object.

## 9. Report

Every run writes `target/conformance/report.json` and prints a markdown capability matrix:

```
| Case | Result | Controls | Evidence |
|---|---|---|---|
| PG-01 | PASS | wrongpass REFUSED, wrongca REFUSED | psql → `ZS_CONFORMANCE_OK` |
| SV-05 | FAIL | n/a | agent refused: `STREAMING- payloads are not signed` |
```

Exit code: 0 only when every case passed and no case skipped. The summary line names counts for
PASS, FAIL and SKIPPED, and lists failing IDs.

## 10. Cases that were red on day one

Per decision D2 these failed, CI went red, and that red was honest rather than flaky. Each is
linked to the work that closed it. All three closed on 2026-10-27 on the owner's instruction.

| Case | Why it failed | Closed by |
|---|---|---|
| SV-05 | The agent refused every `STREAMING-` payload (`crates/zs-proto-http/src/signing.rs`, the open item "Streaming SigV4") | The agent now decodes the aws-chunked body, signs the decoded payload and refuses a trailer header: `docs/specs/2026-10-27-streamed-sigv4-uploads.md` |
| SV-06 | A presigned URL stayed valid until `X-Amz-Expires`, at most seven days, by `docs/SECURITY.md` §3 | The owner capped `X-Amz-Expires` at 15 minutes (SECURITY §3) and rewrote SV-06 to assert the cap |
| MG-06 | No nesting-depth guard existed; the `bson` spike names one as a precondition for adopting the library | `crates/zs-proto-mongo` refuses a client `OP_MSG` nested deeper than 100 levels: `docs/specs/2026-10-27-mongo-document-depth.md` |

The builder must confirm each of these is a genuine gap by reading the code before accepting a red,
because a red that is really a test bug poisons the whole signal. Any case found red for a fourth
reason is reported to the owner before the plan continues.

## 11. Calls made here, for the owner to check

Decisions a sensible builder could have made, made here so the plan is unambiguous. None changes
what the suite proves.

1. `tokio-postgres` as a dev-dependency, for the extended protocol and binary COPY only
   (section 6.3). `psql` cannot reach the extended protocol.
2. The official SigV4 vectors are **vendored** under `vectors/`, with provenance and licence in
   `VECTORS.md`, rather than fetched at test time. CI must not depend on the network.
3. Case IDs are test names, so `cargo test -p zs-conformance PG-04` selects one case.
4. Negative controls are derived automatically from each positive rather than written by hand, so
   a new positive cannot ship without its two controls.
5. The suite does not start Docker fixtures; it detects and reports them. Starting containers from
   a test has OOM-killed a fixture on this Mac before.
6. `--allow-skips` exists for a developer laptop with only the default profile up. CI never passes
   it.
7. The three pieces in section 6.4: the suite provisions its own roles, runs its own fake HTTP
   upstream that verifies SigV4 signatures rather than key ids, and generates its own wrong CA.
   Each exists because reusing a ZeroSecret-specific artefact would break section 6.5.

## 12. Left to the builder

- The exact `tests/conformance.rs` harness shape: one `#[test]` per case, or one test that drives
  the registry and reports per case. Either satisfies section 6.5 rule 3.
- How `adapters/zerosecret.sh` discovers a free port and waits for the listener. `free_port()` and
  the `wait_for_file` idiom in `apps/zs/tests/common/mod.rs` are prior art.
- Whether MG-03's payload-type-1 section is driven through `mongosh` or a raw socket.
- The MySQL `COM_RESET_CONNECTION` path: the `mysql` CLI exposes it only indirectly.

## 13. Open for the owner

1. **CI wiring.** The suite needs a job in `.github/workflows/ci.yml`, which agents are told never
   to stage. The owner either adds the job or grants the exception. Until then the suite runs only
   locally and decision D2's "red CI" has no teeth.
2. **Ordering against the hyper plan.** This suite does not depend on
   the hyper-proxy plan (not published), Task 2: that task covers HTTP/1 framing against
   ZeroSecret's own proxy, and nothing in the four protocols above touches it. The SigV4 cases use
   the official vectors as their oracle, not Task 2's fixtures. Recommendation: start in parallel.
