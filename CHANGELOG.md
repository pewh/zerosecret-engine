# Changelog

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

## 0.1.0

First source release under Apache-2.0. No crates.io packages and no binaries.

- `zs`, the agent CLI. It runs a workload without credentials and adds them to outbound
  requests that a signed grant allows.
- Brokered protocols: HTTP and HTTPS (header injection and AWS SigV4 signing), PostgreSQL,
  MySQL and MongoDB.
- `zs-verify`, which reports whether a credential value reached the workload's environment,
  files or arguments.
- `zs-conformance`, the protocol conformance suite, with the AWS SigV4 test vectors.
