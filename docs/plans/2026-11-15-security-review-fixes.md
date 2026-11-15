# Security Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the six proven findings of the 0.6.0 security review (commit 616216d), so that each of the 15 saved failing tests passes, and correct the documents where they differ from the code.

**Architecture:** Each finding is one small change in the crate that owns the behaviour, proven by a test that already exists and fails today. Finding 0.1 adds one session check to `zs-protocol` that travels with the credential, and a 5 s re-check to the four database relays, the same rule the WebSocket relay already has ([session-end spec](../specs/2026-11-15-database-session-end.md)). The other five findings are local filters. One ADR records the two behaviour changes (0.1 and `Range`) before the code changes.

**Tech Stack:** Rust (toolchain in `rust-toolchain.toml`), tokio, hyper, the per-crate fake upstreams in `crates/zs-proto-*/tests/fake/`.

**Spec:** this file, and for Task 2 the [session-end spec](../specs/2026-11-15-database-session-end.md) (accepted 2026-11-15), which owns the types. The review notes are deleted; the section "Findings" below is the record. The saved failing tests are in `security-review-tests.local/` (same relative paths as their place in the repository). The test folder is git-excluded and must never be committed. Do not push this plan while a finding is open: this repository is public.

## Findings

| Id | Severity | What is wrong at 616216d | Decisive lines |
|---|---|---|---|
| 0.1 | Medium | An open PostgreSQL, MySQL, MongoDB or Redis session continues after grant revocation or expiry. The grant is checked once per connection | `apps/zs/src/run.rs:246-275`; relays at `zs-proto-postgres/src/lib.rs:2368`, `zs-proto-mysql/src/lib.rs:829`, `zs-proto-mongo/src/lib.rs:984`, `zs-proto-redis/src/lib.rs:726` |
| 2.1 | Low | Two `Range` requests return an echoed credential in two parts; each response passes the echo guard | `crates/zs-mitm/src/pipeline.rs:176-182`, `http1.rs:26-33`, `echo.rs:210-213` |
| 1.1 | Low | `CONNECT <database resource name>:<port>` matches the database binding, and the proxy then uses the http binding that has the same `host` | `apps/zs/src/lib.rs:1036`, `:1071-1073`, `:1221`, `:1256-1265` |
| 4.1 | Low | `zs init` leaves a brokered password in `.env` under a second key or inside a DSN and does not list the key; `_PASS` and `_PWD` keys are not listed | `apps/zs/src/init.rs:48-56`, `:495-506`, `:675`, `:740` |
| 3.1 | Low | The MongoDB relay forwards an `OP_MSG` with two body sections; the second can be `saslStart` | `zs-proto-mongo/src/lib.rs:845-868`, `wire.rs:173-188` |
| 3.2 | Low | The MySQL relay forwards `COM_CHANGE_USER` when the packet sequence id is not 0 | `zs-proto-mysql/src/lib.rs:784-786` |
| G1 | Doc gap | `zs init` prints `written (0600)` for an existing file that is 0644 | `apps/zs/src/init.rs:1145-1155`, `:1407-1412` |
| G2 | Doc gap | A `file` reference with a `.` part or an empty part resolves; `docs/SECURITY.md:533-534` says it is refused | `crates/zs-materializer/src/lib.rs:135-147` |

## Global Constraints

- Line numbers are those of 616216d. Confirm each with the code before you edit.
- No comments or inline documentation in new code (`AGENTS.md` "Output contract").
- Fail closed. Client-visible refusal text is fixed text; it never repeats an argument.
- No credential value in a log line, an audit record, an error message or a panic payload.
- Do not weaken an existing test or a security claim to make a test pass.
- `docs/DECISIONS.md` is newest first; add a new entry, never edit an old one. `docs/specs/*.md` are immutable.
- Documents use ASD-STE100: short sentences, active voice, one word for one thing.
- Do not commit, tag or push unless the owner asks. Where a step says "Commit", it means: stage the named files and stop for the owner; if the owner asked for commits, use `git commit -s`.
- This plan is committed by owner decision. Do not push it while a finding is open: this repository is public. Never commit `security-review-tests.local/`. A copied test file is committed only together with its fix.
- Disk: check `df -h` before each build. Build one crate at a time with `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only`. Run `cargo clean` at the end if `target/` is over 20 GB.
- Per-crate gate after each task: `cargo test -p <crate>`, `cargo fmt --all -- --check`, `cargo clippy -p <crate> --all-targets -- -D warnings -A clippy::unwrap_used -A clippy::expect_used -A clippy::panic`.
- Do not start Docker and do not use the login keychain. Tests in `apps/zs/tests` that start the agent need a disposable keychain; the three `review_*` files there need none.

## Review Focus

1. **A relay does not await its `SessionWatch`, or the glue builds a check that always passes.** The session then outlives its grant again. Pinned in Task 2, step 2 (one test for each relay) and step 9 (two tests on the closure that the glue builds).
2. **A session with a valid, renewed grant is closed by the re-check.** A pool would lose every connection each 5 s. Pinned in Task 2, step 2 (the session survives 6 s while the grant is valid).
3. **A ranged S3 download through an `aws-sigv4` binding.** `Range` can be a signed header; removing it breaks the request. Pinned in Task 3, step 3.
4. **A MySQL packet of exactly 16 MiB - 1 bytes whose continuation packet starts with `0x11`.** It is data, not a command, and must be forwarded. Pinned in Task 6, step 2.
5. **`zs init` with a short brokered password** (for example `app`). A containment test would report nearly every line. Pinned in Task 5, step 2.

---

### Task 1: ADR for the two behaviour changes

**Files:**
- Modify: `docs/DECISIONS.md` (new entry at the top, the next free number after ADR-0058)

`AGENTS.md` hard rule 1: a trust-boundary change starts with a spec or an ADR.

- [x] **Step 1 (done 2026-11-15, ADR-0059, unstaged): Write the ADR entry "Database sessions end on revocation; `Range` is removed from credential-bearing requests".** It decides exactly this:
  - Each database relay (PostgreSQL, MySQL, MongoDB, Redis) checks the grant again every 5 s, with the same check as a CancelRequest (`authorize_message(resource, "connect")`: revocation, signature and expiry, connection match). The first check runs 5 s after the relay starts.
  - On a denial the agent closes both directions and writes no reply. It audits `deny` `connect` with the fixed reason `grant revoked`, and the diagnostic `conn_closed` event has the code `revoked`.
  - A renewed grant keeps the session open, because the check reads the current grant of the resource.
  - The check reaches the relay with the credential: `Materialize` returns both, so a listener cannot take the credential without the check ([session-end spec](../specs/2026-11-15-database-session-end.md)).
  - On an injected request whose scheme sends the credential (`bearer`, `basic`, `api-key-header`, `query-param`) the agent removes `Range` and `If-Range`. The signing schemes (`aws-sigv4`, `hmac-body-signature`) keep them: they never send the secret, so the upstream cannot return it.
  - Consequence to state: a ranged download through a `bearer` binding becomes a full download. "Reverse it if" a supported client needs ranged downloads with a bearer credential; then the replacement is to refuse a 206 answer whose body the guard cannot bound.
  - Corrects, by reference, the words of ADR-0026 ("revoking any ID in that chain stops the session") for database sessions: true from this ADR on.
- [x] **Step 2 (done 2026-11-15 in the document commit, ADR-0059): Commit** `docs/DECISIONS.md` (`docs(adr): database sessions end on revocation, Range removed`).

---

### Task 2: Finding 0.1, re-check the grant in the four database relays

Rewritten 2026-11-15 after the owner accepted the [session-end spec](../specs/2026-11-15-database-session-end.md). That spec owns the signatures; this task does not restate them. `Revalidate`, `with_revalidate` and `listen_revalidated` are not built.

**Files:**
- Modify: `crates/zs-protocol/Cargo.toml` (feature `session`; the workspace `tokio` as an optional dependency of that feature), `crates/zs-protocol/src/lib.rs` (`Materialize`, line 45)
- Modify: `crates/zs-proto-{redis,postgres,mysql,mongo}/Cargo.toml` (enable `session`) and `src/lib.rs` (the `materialize` call in the handshake, `serve`, `relay`, the `AuditRefusal` alias)
- Modify: each test that builds a `Materialize`: `crates/zs-proto-{redis,postgres,mysql,mongo}/tests/fake/mod.rs`, `crates/zs-proto-mysql/tests/listener.rs`, `crates/zs-proto-redis/tests/listener.rs`, `crates/zs-proto-redis/tests/redis_real.rs`
- Modify: `crates/zs-mitm/src/websocket.rs:15` (reads the shared constant)
- Modify: `apps/zs/src/run.rs:246-275` (`l3_materialize`); the four listener builds do not change
- Modify: `apps/zs/Cargo.toml` (enable `session`; `tokio` `test-util` as a dev-dependency), `apps/zs/tests/postgres_real.rs` (builds a `Materialize`)
- Test (copy from `security-review-tests.local/`): `crates/zs-proto-{redis,postgres,mysql,mongo}/tests/review_session_outlives_grant.rs`, renamed to `session_ends_with_grant.rs`

**Interfaces:**
- Produces, in `zs-protocol`: `REVALIDATE_EVERY`, `SessionCheck`, `Materialized`, `SessionWatch`, the new `Materialize`, `AuditRefusal` and `admitted`, as the spec's section "Types in `zs-protocol`" gives them.
- Each relay crate re-exports `Materialize` and `AuditRefusal`. The fake `listen` helpers keep their signatures.
- Fixed strings: audit operation `connect`, audit reason `grant revoked`, close code `revoked`.

- [x] **Step 1: Copy the four test files into place** under the new name `session_ends_with_grant.rs`.
- [x] **Step 2: Adapt each test.** `grant_state()` returns `(Materialize, Arc<AtomicBool>)`. The `Materialize` returns `Materialized::new(credential, check)`; the check returns `Ok(())` while the flag is true and `Err("grant revoked")` after. The listener is built with the existing `listen` helper. Add one assertion before the flag changes: sleep 6 s, send a command with the marker `still-granted`, and assert that the fake upstream received it (Review Focus 2). Keep both controls and the final assertion as they are.
- [x] **Step 3: Run one test to verify it fails to compile.** Run: `cargo test -p zs-proto-redis --test session_ends_with_grant`. Expected: error, `Materialized` not found.
- [x] **Step 4: `zs-protocol`.** Add the feature and the items of the spec. Add the four unit tests that the spec's section "Tests" names for `zs-protocol`; use paused tokio time. Run: `cargo test -p zs-protocol --features session`. Expected: PASS. From this step until step 9, `zs` does not compile; build one crate at a time.
- [x] **Step 5: Redis.** The handshake calls `into_parts` and `Session` carries the `SessionWatch`. In `relay` (`:726-811`), add a third branch to the outer `tokio::select!` that awaits `SessionWatch::ended`, and a new `Ending::Revoked(&'static str)` whose `code()` is `revoked`. On it: `conn.refused("revoked", conn.audit(reason))`, no reply written, both halves dropped. `serve` calls `zs_protocol::admitted`. The local `AuditRefusal` alias becomes a re-export. In `tests/fake/mod.rs` and the two other test files, each `Materialize` wraps its credential with a check that returns `Ok(())`.
- [x] **Step 6: Run the Redis test.** Run: `cargo test -p zs-proto-redis --test session_ends_with_grant`. Expected: PASS (about 12 s). Then `cargo test -p zs-proto-redis`: all pass.
- [x] **Step 7: PostgreSQL, MySQL, MongoDB.** The same change in each crate (`relay` at `postgres :2368-2402`, `mysql :829-880`, `mongo :984+`), with each crate's own refusal-audit call and close event. PostgreSQL aborts both copy tasks and reports `closed_by` `revoked`. `zs_proto_postgres::CancelAuthorize` stays.
- [x] **Step 8: Run the three tests and each crate's full suite.** Run, one at a time: `cargo test -p zs-proto-postgres`, `cargo test -p zs-proto-mysql`, `cargo test -p zs-proto-mongo`. Expected: all pass, the three new tests included.
- [x] **Step 9: Glue.** In `apps/zs/src/run.rs`, `l3_materialize` builds the check beside the credential: the check calls `audit.handler.authorize_message(&audit.resource, "connect")` and maps a denial to `grant revoked`; an allowed outcome returns `Materialized::new(credential, check)`. The audit record of the `connect` and the audit-unavailable denial stay as they are. Add three unit tests in the `run.rs` test module on the closure that `l3_materialize` builds: `the_session_check_denies_after_revocation`, `the_session_check_denies_after_expiry` and `the_session_check_passes_after_renewal`. The renewal test lets the first grant expire; it does not revoke it, because a revoked grant ID stays in the chain of its renewal (ADR-0026). `crates/zs-mitm/src/websocket.rs` reads `zs_protocol::REVALIDATE_EVERY`. Run: `cargo test -p zs --bin zs the_session_check` (`run.rs` is in the binary target), then `cargo test -p zs-mitm --lib websocket`. Expected: PASS.
- [x] **Step 10: Documents.** `docs/SECURITY.md:141-149`: add that an open database session is checked every 5 s and ends within 5 s of a revocation the agent has learned of, or of grant expiry, with no reply. Add one §7 row after the "Grant revoked" row (`:925`): "Grant revoked or expired while a PostgreSQL, MySQL, MongoDB or Redis session is open | Close the connection within 5 s, no reply. Audit `deny` `connect`, reason `grant revoked` (ADR of Task 1)". `docs/ARCHITECTURE.md`: add the re-check where the L3 relay is described, if it is.
- [x] **Step 11: Gate and commit.** Per-crate gate for `zs-protocol` (with `--features session`), the four relay crates, `zs-mitm` and `zs`. Run the four `grep` checks of the spec's section "Verification". Commit: `fix(l3): end an open database session when its grant is revoked or expires`.

---

### Task 3: Finding 2.1, remove `Range` from requests that carry the credential

**Files:**
- Modify: `crates/zs-protocol/src/lib.rs` (`Protocol` trait, line 136)
- Modify: `crates/zs-proto-http/src/signing.rs` (the `aws-sigv4` and `hmac-body-signature` impls)
- Modify: `crates/zs-mitm/src/pipeline.rs:176-182`
- Test (copy): `apps/zs/tests/review_range_splits_echo.rs`, renamed to `range_on_injected_request.rs`

**Interfaces:**
- Produces: `fn keeps_range(&self) -> bool { false }` as a default method on `zs_protocol::Protocol`; the two signing protocols return `true`.

- [ ] **Step 1: Copy the test into place** and run it. Run: `cargo test -p zs --test range_on_injected_request`. Expected: FAIL, "two `Range` requests returned the injected credential".
- [ ] **Step 2: Add `keeps_range` to the trait and the two overrides.**
- [ ] **Step 3: Write the sigv4 test** in the unit tests of `crates/zs-mitm/src/pipeline.rs` (use the existing test handler there, `:547`): `a_signing_scheme_keeps_the_range_header` asserts that an injected request through a protocol with `keeps_range() == true` still has `Range: bytes=0-9`, and `a_credential_scheme_loses_range_and_if_range` asserts that both headers are gone when it is `false`. Run: `cargo test -p zs-mitm --lib range`. Expected: the second test FAILS.
- [ ] **Step 4: Implement.** In the closure at `pipeline.rs:176-181`, after `protocol.inject(...)` succeeds: `if !protocol.keeps_range() { request.remove_header("Range"); request.remove_header("If-Range"); }`.
- [ ] **Step 5: Run.** `cargo test -p zs-mitm --lib range` and `cargo test -p zs --test range_on_injected_request`. Expected: PASS. Then `cargo test -p zs-mitm` and `cargo test -p zs-proto-http`: all pass.
- [ ] **Step 6: Documents.** `docs/SECURITY.md` §4 rule 9 (`:513-528`): add "An injected request on a scheme that sends the credential loses `Range` and `If-Range`, so the workload cannot ask for an echoed value in parts." Add one §7 row after `:1005` with the same fact.
- [ ] **Step 7: Gate and commit.** `fix(mitm): remove Range from requests that carry the credential`.

---

### Task 4: Finding 1.1, the proxy ignores database bindings

**Files:**
- Modify: `apps/zs/src/lib.rs:1219-1223` (`classify`)
- Test (copy): `apps/zs/tests/review_database_name_as_proxy_host.rs`, renamed to `database_name_is_not_a_proxy_host.rs`

- [ ] **Step 1: Copy the test into place** and run it. Run: `cargo test -p zs --test database_name_is_not_a_proxy_host`. Expected: 3 FAIL.
- [ ] **Step 2: Implement.** In `classify`, a binding found by `binding_for` is used only when `!binding.is_l3()`; else return `Flow::Passthrough`. Leave `credential_ref` (`:1332-1339`) unchanged.
- [ ] **Step 3: Run.** The same command. Expected: 3 PASS. Then `cargo test -p zs --lib`: all pass.
- [ ] **Step 4: Gate and commit.** `fix(proxy): a database resource name is not a proxy host`.

---

### Task 5: Finding 4.1 and gap G1, `zs init` reports every copy and fixes the file mode

**Files:**
- Modify: `apps/zs/src/init.rs` (`classify` `:495-506`, the plan step after `:740`, the existing-file branch `:1145-1155`, `REDIS_REASON` `:38`)
- Test (copy): `apps/zs/tests/review_init.rs`, renamed to `init_leftover_secrets.rs`

**Interfaces:**
- Fixed text for a leftover copy: `holds a value that zs init brokered under another key; remove it by hand`. It is printed by the existing `zs: not brokered, left in .env: <KEY> (<reason>)` line.

- [ ] **Step 1: Copy the test into place** and run it. Run: `cargo test -p zs --test init_leftover_secrets`. Expected: 4 FAIL.
- [ ] **Step 2: Add the short-value test** to the same file: `a_short_brokered_password_reports_only_its_exact_copy`. `.env`: `MYSQL_HOST=db.example.internal`, `MYSQL_USER=app`, `MYSQL_PASSWORD=app`, `MYSQL_PWD=app`, `APP_NAME=my-app-service`. Assert: `MYSQL_PWD` is listed as not brokered; `APP_NAME` and `MYSQL_USER` are not listed.
- [ ] **Step 3: Implement the leftover report.** After planning, for each `.env` line that is not rewritten: report it with the fixed text when its value equals a brokered raw value, or contains a brokered raw value of 8 bytes or more. "Brokered raw value" is the value as it stood in `.env` (for a Basic pair, the secret, not the base64 token). `MYSQL_USER` is exempt because the user key of a brokered group is never reported.
- [ ] **Step 4: Extend the name rule.** In `classify` (`:500`), a key that ends with one of `PASSWORD_SUFFIXES` (`:16`) is reported as the `SECRET_KEY_WORDS` keys are.
- [ ] **Step 5: File mode (G1).** In the existing-file branch (`:1145-1155`), after the value compare, set the file mode to `0o600` on Unix; an error stops `zs init` before `.env` changes, as the other errors of that function do.
- [ ] **Step 6: Redis text.** Change `REDIS_REASON` (`:38`) to `zs init does not write Redis bindings; write the binding by hand`. Update the tests in `apps/zs/tests/init_cli.rs` that assert the old text.
- [ ] **Step 7: Run.** `cargo test -p zs --test init_leftover_secrets` (5 PASS) and `cargo test -p zs --test init_cli` (all pass).
- [ ] **Step 8: Documents.** `README.md:206`: say that a second copy of a brokered value is listed, and that an existing credential file is set to 0600.
- [ ] **Step 9: Gate and commit.** `fix(init): list every leftover copy of a brokered secret, set 0600 on an existing file`.

---

### Task 6: Findings 3.1 and 3.2, the two relay filters

**Files:**
- Modify: `crates/zs-proto-mongo/src/wire.rs` (new function next to `command_name`, `:173`), `crates/zs-proto-mongo/src/lib.rs:845-856`
- Modify: `crates/zs-proto-mysql/src/lib.rs:773-805` (`forward_commands`)
- Test (copy): `crates/zs-proto-mongo/tests/review_second_body_section.rs` as `second_body_section.rs`; `crates/zs-proto-mysql/tests/review_change_user_sequence.rs` as `change_user_sequence.rs`

**Interfaces:**
- Produces: `pub fn body_sections(payload: &[u8]) -> Result<usize, Malformed>` in `zs-proto-mongo/src/wire.rs`: the number of kind 0 sections, walking the sections as `exceeds_depth` does.

- [ ] **Step 1: Copy both tests into place** and run them. Run: `cargo test -p zs-proto-mongo --test second_body_section`, `cargo test -p zs-proto-mysql --test change_user_sequence`. Expected: both FAIL at the last assertion.
- [ ] **Step 2: Write the MySQL continuation test** in `change_user_sequence.rs`: `a_continuation_packet_that_starts_with_0x11_is_forwarded`. Send one command as two packets: sequence 0 with exactly `0xff_ffff` payload bytes (`0x03` then filler), then sequence 1 whose payload starts with `0x11` and holds a marker. Assert that the fake upstream received the marker and that the session is still open. Run it. Expected: PASS today; it must still pass after step 4.
- [ ] **Step 3: MongoDB.** Add `body_sections`; in the relay, after the `exceeds_depth` match (`:851-855`), a result other than `Ok(1)` returns `Ending::Refused("malformed")`. Add a unit test in `wire.rs` for 0, 1 and 2 body sections and for a kind 1 section before the body.
- [ ] **Step 4: MySQL.** In `forward_commands`, keep `let mut command_start = true;`. Replace both `header[3] == 0 &&` conditions (`:784`, `:787`) with `command_start &&`. After each packet set `command_start = len < 0xff_ffff`.
- [ ] **Step 5: Run.** Both test files PASS; then `cargo test -p zs-proto-mongo` and `cargo test -p zs-proto-mysql`: all pass.
- [ ] **Step 6: Documents.** `docs/SECURITY.md:944`: add "an `OP_MSG` that does not have exactly one body section" to the list. `:936`: add "whatever its sequence id".
- [ ] **Step 7: Gate and commit.** `fix(l3): refuse a second OP_MSG body section and COM_CHANGE_USER at any sequence id`.

---

### Task 7: Gap G2 and the remaining document corrections

**Files:**
- Modify: `crates/zs-materializer/src/lib.rs:135-147`
- Modify: `docs/SECURITY.md`, `docs/DECISIONS.md` (one new entry, the next free number; ADR-0059 to ADR-0061 are taken), `CHANGELOG.md`
- Test (copy): `crates/zs-materializer/tests/review_file_reference.rs` as `file_reference_parts.rs`

- [ ] **Step 1: Copy the test into place** and run it. Run: `cargo test -p zs-materializer --test file_reference_parts`. Expected: FAIL, `["a/./b", "a//b"]` resolved.
- [ ] **Step 2: Implement.** In `FileStore::read`, after the leading `/` is removed and `..` is replaced, refuse the reference as not resolvable when any part of `relative.split('/')` is empty or is `.`. The existing unit test at `lib.rs:351-361` (`/../secret` resolves to `__/secret`) must still pass.
- [ ] **Step 3: Run.** The test PASSES; `cargo test -p zs-materializer`: all pass.
- [ ] **Step 4: `docs/SECURITY.md` corrections**, one sentence each:
  - `:533-534`: "a leading `/` is dropped, `..` becomes `__`, and a drive prefix, an empty part or a `.` part is refused".
  - `:124-128` and `:527-528`: for a `basic` binding the matched value is the stored base64 token; the decoded `user:secret` is not matched.
  - `:955` and `:423-424`: an `aws-sigv4` request with no `Authorization` header is forwarded unsigned only when the workload holds a grant for the method.
  - After `:402`: a PostgreSQL or MySQL client can change the password of its own account (`ALTER ROLE`, `ALTER USER`, `SET PASSWORD`); that password then works without the agent. Give the advice the MongoDB and Redis paragraphs give (least rights; MySQL `PASSWORD REQUIRE CURRENT`).
  - `:380-383`: the Redis guard matches the raw credential only; `ACL LIST` and `ACL GETUSER` return its SHA-256. Redis 5 and earlier has no ACL, so the advice cannot be applied there.
  - `:935` and §4 rule 7: the diagnostic log can hold a user or database name inside server error text.
  - `:218-219`: the cite `apps/zs/src/lib.rs:1055-1066` is stale; `materialize` and `authorized` are the functions to name.
  - New paragraph near `:388`: a PostgreSQL client sees the agent's denial reason (resource name, grant ID, journal path on an audit failure); it never holds a credential value.
- [ ] **Step 5: `docs/DECISIONS.md`**: one new entry, with the next free number, that amends ADR-0028: the `materialize_failed` event also has `credential_ref`, and for some errors `step` and `provider_code`.
- [ ] **Step 6: `CHANGELOG.md`**: one "Security" section that lists the six fixes in one line each.
- [ ] **Step 7: Full gate.** Check `df -h` first. Run `cargo fmt --all -- --check`, then `cargo clippy --workspace --all-targets -- -D warnings -A clippy::unwrap_used -A clippy::expect_used -A clippy::panic` if 12 GB or more is free, else per crate. Run `cargo test -p <crate>` for each crate this plan changed.
- [ ] **Step 8: Commit** (`fix(materializer): refuse a file reference with an empty or dot part`; `docs: security review corrections`). Then delete `security-review-tests.local/` and this file.

---

## Not in this plan

- Tests against real servers (`*_real.rs`, the conformance suite) and the agent-spawning tests in `apps/zs/tests`: they need Docker or a disposable keychain. The owner or CI runs them before a release.
- The "leads not confirmed" of the review (MySQL user name and client character set, the WebSocket fragment-scanner memory growth, Redis 5 behaviours). None is proven.
- A release. After the tasks land, the owner decides on 0.6.1. This release comes before the engine release of the read-only database access plan (its T9): that plan's T2 needs Task 2 of this plan, and a security fix does not wait for a feature.
