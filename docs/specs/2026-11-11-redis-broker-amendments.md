# Redis broker amendments: an upstream with no password, empty lines, refusal delivery

Status: accepted 2026-11-11. Amends R1, R2 and R4 of
[2026-11-10-redis-broker.md](2026-11-10-redis-broker.md). O1-O5 are the owner's choice (opt-in per
binding); E1-E3 come from the conformance suite (RD-04, RD-06).

## Problem

A development Redis often has no password, while staging and production have one. Under R1 the
agent refuses a Redis with no password, so one application configuration cannot go through the
agent in both places. The workload then keeps a direct path to its development Redis.

R1 also has a gap. The agent sends `AUTH <user> <credential>` when the binding names a user. A
Redis whose `default` user has no password (`nopass`) accepts `AUTH default <anything>`, so a
binding with `user: "default"` is served by an open Redis while a binding without `user` is
refused.

## What Redis does

Redis 6 and later answer the one-argument `AUTH <password>` with
`-ERR AUTH <password> called without any password configured for the default user. ...` when the
`default` user has `nopass`. Redis 5 and earlier answer `-ERR Client sent AUTH, but no password is
set`. Both texts are fixed in the server. A two-argument `AUTH default <x>` and `HELLO 3 AUTH
default <x>` succeed on such a server.

## Design

| Id | Rule |
|---|---|
| O1 | For the `default` user (a binding without `user`, or with `user: "default"`), the agent sends the one-argument `AUTH <credential>`. A named non-default user keeps `AUTH <user> <credential>` |
| O2 | A `redis` binding may set `upstream_auth_optional: true`. When the upstream answers O1 with one of the two fixed texts, the agent serves the connection: no client byte is read before that reply, the diag event is `upstream_auth_not_required` (warn), and the `connect` grant and audit record are unchanged |
| O3 | Without `upstream_auth_optional`, that answer is refused as today: `-ERR ZeroSecret upstream authentication failed`, audit `deny` `connect`, reason `upstream authentication failed` |
| O4 | Any other error, including `WRONGPASS`, is refused with or without the field. A binding that names a user the open server lacks is refused |
| O5 | The field is allowed only on a `redis` binding. It is a local binding field, not part of the signed connection |

The agent still materializes the credential and sends it in O1 before it reads the reply, so a
grant and a credential source are still required. The credential reaches the signed host only,
as before; serving the open server exposes it to nobody new. A client `AUTH` after an open
upstream is rewritten as R2 says and the server's answer is relayed.

## Relay fixes

| Id | Rule |
|---|---|
| E1 | A bare `\r\n` between client frames is skipped, as Redis skips an empty inline line. It carries no command and nothing is forwarded. Any other non-RESP byte is still refused (R4). `redis-cli --pipe` ends its input with one |
| E2 | When a client frame is refused (R3, R4), the agent forwards nothing more and first relays the replies to the frames it already forwarded, for at most 2 s, then writes the fixed error. Replies stay in pipeline order (R2). An echo (R5) or a redirect (R6) during that wait still wins |
| E3 | After any fixed error the agent half-closes the connection and reads and discards what the client still sends, for at most 2 s and 64 MiB, before it closes. A client that is still writing a large first frame then reads the error instead of a reset |

## Security row

One §7 row: a Redis with no password and a binding without `upstream_auth_optional` is refused
with the fixed text and audited, including a binding with `user: "default"`.
