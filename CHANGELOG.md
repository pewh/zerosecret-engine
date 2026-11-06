# Changelog

## [Unreleased]

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
