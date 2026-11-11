# Redis broker

Status: accepted 2026-11-11.

## Problem

An application that talks to Redis holds the Redis password in its environment. The agent brokers
PostgreSQL, MySQL and MongoDB logins, but not Redis, so the password stays in `.env`. A Go service
on `go-redis` v9 against a managed single-node Redis with in-transit TLS is the first user.

## What the client does

`go-redis` v9 opens every pooled connection with `HELLO 3 AUTH <user|default> <password>`. If the
server answers an error, it falls back to `AUTH [<user>] <password>`. It then pipelines
`CLIENT SETINFO LIB-NAME`, `CLIENT SETINFO LIB-VER` and, for a database index above 0, `SELECT`.
Other clients send `AUTH` alone, or no authentication when no password is set. All of them send
RESP arrays of bulk strings; none sends inline commands.

## Design

A `redis` binding opens a loopback listener, as the other L3 protocols do (`ZS_<RESOURCE>_HOST`,
`ZS_<RESOURCE>_PORT`). Per client connection:

| Id | Rule |
|---|---|
| R1 | The agent opens the upstream connection (TCP, then TLS per the binding's upstream TLS mode) and sends `AUTH [<user>] <credential>` before it reads from the client. `+OK` continues; any error answers the client with a fixed error and closes. The credential comes from the materializer once per connection |
| R2 | The agent parses every client frame. An `AUTH` frame, and the `AUTH <user> <password>` arguments of a `HELLO` frame, are rewritten in place to the binding's user and the credential and forwarded, so replies stay in pipeline order. The client's password argument is discarded unread |
| R3 | A client `AUTH` or `HELLO AUTH` that names a user other than the binding `user` (or other than `default` when the binding has no `user`) is refused with a fixed error and the connection closes |
| R4 | A frame that is not a RESP array of bulk strings (an inline command, a RESP3 attribute, an oversized header) is refused with a fixed error and the connection closes |
| R5 | No 8-byte window of the credential reaches the client stream. The agent scans upstream bytes before it writes them; on a match it writes nothing more and closes (the WebSocket echo rule, applied to Redis) |
| R6 | A `-MOVED` or `-ASK` reply closes the connection with a fixed error: cluster redirects name nodes the agent does not broker |
| R7 | Client TLS to the listener is refused (first byte `0x16`); the listener is loopback plaintext. Upstream TLS follows the binding: verified by default, `ca-sha256` and `pin-sha256` allowed, plaintext only with `upstream_plaintext` |
| R8 | Every other command is relayed unchanged, including `SELECT`, `CLIENT SETINFO`, `MULTI`, scripts and pub/sub |
| R9 | One `connect` audit record per admitted connection; refusals are audited with a fixed reason. A grant for a `redis` resource carries the operation `connect` |

Fixed client errors (RESP simple errors, no argument echoed):

| Case | Text |
|---|---|
| Not granted | `-ERR ZeroSecret denied the connection` |
| Upstream unreachable or TLS failure | `-ERR ZeroSecret upstream unavailable` |
| Upstream refused the credential | `-ERR ZeroSecret upstream authentication failed` |
| R3 | `-ERR ZeroSecret refused AUTH for another user` |
| R4 | `-ERR ZeroSecret refused a non-RESP command` |
| R5 | none: the connection closes |
| R6 | `-ERR ZeroSecret refused a cluster redirect` |

## Non-goals

Redis Cluster and Sentinel; client-side TLS to the listener; brokering a password a command
carries as data (`MIGRATE ... AUTH`, `ACL SETUSER`, `CONFIG SET requirepass`). The owner gives the
brokered ACL user no `@admin` or `@dangerous` rights, so the workload cannot change the credential
or read it back through `CONFIG GET`; R5 still closes the stream if a reply carries it.

## Security rows

Five §7 rows, numbered after the last row when the work lands: R1 with a wrong credential gives
the fixed text and no `upstream_auth_ok`; R3 refuses another user's `AUTH` and the upstream never
sees it; R4 refuses an inline `AUTH`; R5 closes before any credential window reaches the client;
R6 closes on `-MOVED`.
