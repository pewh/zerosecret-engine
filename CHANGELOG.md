# Changelog

## [Unreleased]

### Security

- A PostgreSQL, MySQL, MongoDB or Redis resource can be read-only (ADR-0063). A policy resource
  has `access: read_only`, and the control plane signs it into the grant, which is then version 2.
  A read-write grant has no `access` record and stays version 1, byte for byte. This is a
  guardrail, not a security boundary: whoever holds the database password can connect without
  the agent. A database account with read privileges only is the control that stops writes.
  `zs resources` ends the row of such a resource with `read-only (guardrail)`.
- An agent from 0.6.1 or older refuses a read-only grant: its signature does not verify there.
  Update the agent before the control plane issues the first one.
- PostgreSQL and MySQL: the agent opens the session in the database's read-only mode and refuses
  the known ways to switch it off. The agent also refuses a read-only session to a MariaDB
  server. `SHOW default_transaction_read_only` is refused by name, as are
  `SET SESSION CHARACTERISTICS ... READ WRITE` and `SET SESSION TRANSACTION READ WRITE`.
- PostgreSQL refusals: a refused `Query` fails with SQLSTATE `25006`. A refused `Parse` fails
  with SQLSTATE `42883` on the function `zs_refused_read_only_resource()`. A `FunctionCall` is
  always refused, so libpq large-object calls fail on a read-only resource.
- MySQL refusals: a refused command fails with error 1792. A refused `COM_STMT_PREPARE` fails
  with error 1295.
- Start of a read-only session: when PostgreSQL does not confirm the read-only mode, or reports
  a single-byte server encoding, the client gets SQLSTATE `08004`
  `zs: the server cannot open a read-only session`. Client `options` that
  the agent cannot read get SQLSTATE `28000`. A MySQL session that the agent cannot start
  read-only gets error 1045.
- MongoDB and Redis: the agent admits an allowlist of read commands and refuses the rest, with
  code 13 (`Unauthorized`) or `-NOPERM read-only resource`. MongoDB transactions
  (`commitTransaction`) and `OP_MSG` messages with a document sequence are refused. Redis
  scripts (`EVAL`, `EVALSHA`, `SCRIPT`, `FUNCTION`), `INFO` and
  `CLIENT SETINFO` are refused. ioredis skips its ready check, because `INFO` is refused, and
  prints a warning; it then works.
- Open sessions close within 5 s when the access of their grant changes or the grant ends. A
  connection pool then opens new sessions.
- On a read-only PostgreSQL resource the agent sends one pipelined unit at a time: it holds
  the next `Query` or extended-protocol unit until the server is ready again.
- Tested against PostgreSQL 16 and 13, MySQL 8.4, MongoDB 8.0 and Redis 7.4: libpq, node-postgres,
  pgx, psycopg, mysql2, the MongoDB Node driver and ioredis read through a read-only session
  and are refused a write.
- Audit, all `deny`: `read-only` for a refused command (operation `query`) and for a refused
  session start (operation `connect`); `read-only escaped` when PostgreSQL leaves the read-only
  mode, or at startup does not confirm it or reports a single-byte encoding; `access changed` when the access of the grant
  changes; `grant revoked` when the grant is revoked or expires; `read-only refusal backlog`
  when a Redis client has 16,384 refused commands that wait for their reply.
- PostgreSQL, every read-only session: `COPY ... TO PROGRAM`, `COPY ... FROM PROGRAM` and
  `COPY ... TO '<server file>'` are refused, also for a login that is not a superuser
  (`pg_execute_server_program`, `pg_write_server_files`). `COPY ... TO STDOUT` works, and so
  does a table named `program`. A statement that names `copy` and later has `program` or `to`
  before a string literal is refused, so `COPY (SELECT ... SIMILAR TO 'x') TO STDOUT` is
  refused too. `lo_export`, `pg_file_write`, `pg_file_rename` and `pg_file_unlink` (server
  files) and `crosstab` with every `crosstab*` name, `connectby` and `xpath_table` (they run
  SQL text) are refused in every read-only session.
- PostgreSQL 13 and older: the server does not report `default_transaction_read_only`, so
  the agent sends `SHOW default_transaction_read_only` once after login and opens the session
  only when the answer is `on`. The client never sees this query. A server whose
  `server_version` is not in the PostgreSQL form (YugabyteDB), or that reports `crdb_version`
  (CockroachDB), cannot be a read-only resource.
- MySQL, every read-only session: the words `restart`, `purge`, `flush`, `reset`, `replica`,
  `replication`, `group_replication`, `slave` and `clone` and the phrases `change master` and
  `alter instance` are refused, so a root-class login cannot run replication, binary log,
  flush, clone, instance or restart statements. `SHOW REPLICA STATUS` is refused too, and so is
  a string literal that is one of these words, such as `'reset'`.
- MongoDB: a read-only session admits `getMore` and `killCursors` only for a cursor that a
  read-only session of the same resource opened (`find`, `aggregate`, `listCollections`,
  `listIndexes`), on any of its connections. A cursor opened in a read-write session, such as
  a `$merge` prepared with `batchSize: 0`, is refused with code 13. The agent forgets a cursor
  when it is exhausted or killed, after 30 min without use, or as the oldest of 65,536.
- MongoDB, every session: a client message that reuses the request id of a message whose
  reply is still awaited closes the session, so one reply cannot be read as the other.
- Limit, PostgreSQL: a read-only resource needs a multi-byte server encoding (`UTF8`, `EUC_JP`,
  `EUC_CN`, `EUC_KR`, `EUC_TW`, `EUC_JIS_2004` or `MULE_INTERNAL`). Poolers that drop the
  server's startup parameters cannot be read-only resources.
- Limit, PostgreSQL 13 and older: the server does not report a later change of the mode, so
  the agent has no backstop there. A switch-off that the scan cannot see, for example inside
  an existing function that calls `set_config`, is not detected.
- Limit, MySQL: a client that sends query attributes is refused. Connector/J 8.1 and later
  sends them when OpenTelemetry is on the classpath; set `openTelemetry=DISABLED`.
- Limit, PostgreSQL and MySQL: a read-only statement text over 64 MiB closes the session.
- Limit, MySQL: binary commands outside the allowlist are refused. A non-Latin value with three
  segments joined by `_` can be refused.
- Limit, MongoDB: a read cursor that a session opened before a switch to read-only cannot be
  continued after it; the driver gets code 13 and runs the query again.
- Limit, Redis: `EVAL_RO`, `EVALSHA_RO` and `FCALL_RO` are refused.

## [0.6.1] - 2026-11-15

### Security

- An open PostgreSQL, MySQL, MongoDB or Redis session ends within 5 s when its grant is revoked
  or expires (ADR-0059).
- An injected request on a scheme that sends the credential loses `Range` and `If-Range`, so an
  echoed credential cannot come back in parts (ADR-0059).
- A database resource name is no longer a proxy host: `CONNECT <database resource>:<port>`
  passes through without a credential.
- A policy file is refused at load when two bindings share a key: a database resource name
  that equals an http or https host, or two http or https bindings on one host. Before, one
  binding silently replaced the other.
- `zs init` lists every leftover copy of a brokered secret in `.env`, lists `_PASS` and `_PWD`
  keys, and sets an existing credential file to 0600.
- The MongoDB relay refuses an `OP_MSG` that does not have exactly one body section; the MySQL
  relay refuses `COM_CHANGE_USER` whatever its sequence id.
- A `file` credential reference with an empty part or a `.` part is refused as not resolvable.

## [0.6.0] - 2026-11-11

- A `redis` binding brokers Redis logins through `RedisListener` (ADR-0057). The agent
  authenticates upstream before it reads the client, rewrites `AUTH` and `HELLO AUTH` in place,
  and never forwards the client's password. It refuses another user's `AUTH`, a non-RESP frame,
  a cluster redirect and a reply that carries an 8-byte window of the credential, with the fixed
  `-ERR` text and a `deny` `connect` audit reason. The grant operation is `connect`.
- A `redis` binding with `upstream_auth_optional: true` serves a Redis that has no password
  (ADR-0058); without it such a server is refused, also when the binding names `user: "default"`.
  An empty line between client frames is skipped, replies to earlier frames arrive before a
  refusal, and a refused client is drained so it reads the error.

## [0.5.0] - 2026-11-08

- Releases publish binaries for five targets (ADR-0056, which lifts ADR-0045 D6):
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`,
  `x86_64-apple-darwin` and `x86_64-pc-windows-msvc`. Each release carries `SHA256SUMS`,
  one CycloneDX SBOM per target and a Sigstore keyless attestation. `publish` creates a
  draft release; the owner verifies it with `tools/verify-release.sh` and publishes it.
- A `windows-agent` CI job runs the proxy, endpoint and PostgreSQL relay tests under
  `zs run` on Windows. A private repository fails `macos-guard` instead of skipping the
  macOS jobs.
- The agent is unchanged from 0.4.0.

## [0.4.0] - 2026-11-07

- The control plane can replace its grant signing key, its federation key and its device CA without
  breaking enrolled devices (ADR-0053). The agent learns the published grant keys and CA
  certificates from the 60-second revocations response, verifies a grant under any published key,
  and trusts a published device CA before it signs. An absent or empty set leaves the agent's
  current set unchanged; a set with one invalid entry is rejected whole. Once the agent holds a
  published CA set, that set is its whole wire trust: a retired CA, even the one pinned at
  enrolment, no longer authenticates the wire. An unchanged set keeps the current connections.
- Grants carry a signed `version`. A grant without the field is version 1 and keeps its exact
  bytes, so a `v0.3.0` control plane keeps working; an agent refuses an unknown version by name
  (`grant version not supported by this zs; upgrade zs`). A device enrolled with an environment
  refuses a grant for another environment (`grant is for another environment`).
- Device certificates expire with the device's standing plus one hour, not after a year.
- Every wire request carries `User-Agent: zs/<version>`, and the control plane logs it as `agent`
  (`zs/<version>`, `none` or `other`).
- SECURITY §7 gains rows 103-105 and 109 (rows 106-108 run in the commercial suite).

## [0.3.0] - 2026-11-07

**Breaking.** A client that drops the proxy userinfo, and a request to the local endpoint whose
path does not start with the run token, are refused. There is no opt-out flag.

- Every local listener of `zs run` authenticates its caller (ADR-0052). `HTTPS_PROXY`, and
  `HTTP_PROXY` for an http binding, carry a per-run token as the proxy userinfo
  (`http://zs:<64 hex>@<addr>`); the proxy answers `407` with
  `Proxy-Authenticate: Basic realm="zs"` when `Proxy-Authorization` is missing or wrong.
  `ZS_<RESOURCE>_URL` carries the token as its first path segment; the endpoint and
  `/.zs/presign` answer `403` when it is missing, and `/.zs/presign` strips the token from a URL
  the client presigned on `ZS_<RESOURCE>_URL` before it re-signs it. Both refusals come before
  grant lookup, materialization and audit, emit one `caller_refused` diagnostic event, and echo
  nothing the caller sent.
- The PostgreSQL, MySQL and MongoDB listeners close a connection unless its peer is an
  established socket of the agent's OS user, before reading a byte and before materialization.
  The check is `inet_diag` on Linux and a walk of the user's processes on macOS, and it runs off
  the async runtime. Windows database listeners do not check (SECURITY §3); any other platform
  refuses every database client.
- A MySQL server that resets the connection in answer to the client's `COM_QUIT` is no longer
  reported as an `upstream_failed` relay error, whichever half of the relay finishes first.
- `Proxy-Authorization` is removed as soon as the proxy admits a request, and it is a hop-by-hop
  header: it never reaches an upstream.
- SECURITY §7 gains rows 98-102. `zs-verify` probes the listener with and without the token,
  reads the token from `/proc/<pid>/environ` on Linux, and reports the listener vector
  `incomplete` when it could probe only without the token. The conformance adapter reads the
  endpoint URL from the child's environment.
- Two `zs run` processes that share a CA directory no longer race on the Bun preload: the file
  is written under a private temporary name and renamed into place, so neither run loses Bun
  WebSocket interception.
- Docs: a non-boolean `email_verified` refuses the sign-in (it does not fall back to `sub`);
  `/logout` shares the control plane's sign-in rate limit; every MySQL binding reads the server
  greeting before any decision, with or without `user`.

## [0.2.0] - 2026-11-06

Security fixes and hardening from the 2026-11-05 deep review. No exploitation detail is given.

- A response to a request that carries an injected credential is scanned: a head or body that
  echoes the credential (raw, percent-encoded, or an injected value) is refused or cut off.
  `TRACE` is refused on such a request and injected requests ask for identity encoding.
- `--listen` must name a loopback address.
- The audit ship cursor is persisted and shipping is batched, so records unshipped at exit
  ship on the next run. `SIGTERM` and `SIGHUP` reach the child and the final ship still runs.
- Header-scheme WebSocket sessions are re-validated every 5 s and end on revocation or grant
  expiry. The echo guard covers control frames and never puts an 8-byte window of the
  credential on the workload's stream.
- `zs init` writes its `.env` backup outside the workspace and masks unbrokered values in
  `--dry-run`.
- The PostgreSQL SCRAM iteration floor is 4096; the control and enrolment URLs are checked
  before any connection; new audit journals are created 0600; a presigned URL is capped at 15
  minutes from `X-Amz-Date`; the `user` binding applies to PostgreSQL and MySQL and a
  differing startup user is refused (PostgreSQL `replication` is always refused); MySQL
  `CLIENT_LOCAL_FILES` is stripped; credential references accept only normal path components.
- Upstream connects try every resolved address, with connect, TLS-handshake and response-head
  timeouts. The local CA root is constrained and leaves are valid for 24 h. The renewal
  lineage is bounded and a torn journal line is repaired. No raw print macro remains in the
  agent.
- A presigned URL is also capped at 15 minutes from now: `X-Amz-Date` plus `X-Amz-Expires`
  may not pass that point.
- `zs login` polls the sign-in claim every 3 s and retries a 429, waiting for `Retry-After`.
- A PostgreSQL CancelRequest needs a live grant for the binding; a protocol 3.2 CancelRequest
  (a key longer than 4 bytes) is dropped before any upstream contact.
- MySQL and MongoDB materialize the credential only after the client has spoken; a MySQL
  binding reads the server greeting first.

## 0.1.0

First source release under Apache-2.0. No crates.io packages and no binaries.

- `zs`, the agent CLI. It runs a workload without credentials and adds them to outbound
  requests that a signed grant allows.
- Brokered protocols: HTTP and HTTPS (header injection and AWS SigV4 signing), PostgreSQL,
  MySQL and MongoDB.
- `zs-verify`, which reports whether a credential value reached the workload's environment,
  files or arguments.
- `zs-conformance`, the protocol conformance suite, with the AWS SigV4 test vectors.
