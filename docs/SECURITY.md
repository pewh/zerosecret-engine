# ZeroSecret Security Model

**Status:** Approved direction
**Date:** 2026-09-05
**Owner of:** trust boundaries, threat model, documented limits, credential handling

> Claims are scoped in [PRODUCT.md §7](PRODUCT.md#7-claims-discipline).
> Mechanisms are in [ARCHITECTURE.md](ARCHITECTURE.md).

A security product that overstates its guarantees is worse than one that states them
plainly. This file exists to be read by a hostile reviewer.

## 1. Trust boundaries

| Boundary | Trusted with |
|---|---|
| Workspace process | Nothing. It is the thing being protected from |
| Agent | Identity, policy cache, grants, materialized credentials in memory for the life of one exchange. For an `aws_ssm` source: a short-lived AWS session, limited by a session policy to one parameter, and the value for the life of its grant (§4 rule 1) |
| Control plane | Identity, org config, credential references, policy, audit. Signs short-lived federation identity tokens (ADR-0041). Never credential values |
| Dashboard | Reads: a session whose subject is a member of the dashboard organization. Writes: the `admin` role in that organization (ADR-0042) |
| Vault provider | Credential values. Customer-operated or customer-chosen |
| Gateway (v2) | Resource-side connectivity, remote materialization |

The control plane (`control/`) never stores a credential value. It stores a reference and
the policy that authorizes its use.

**The IdP's `email_verified` claim decides whether `email` names the signer-in (D2).** The
control plane uses the `email` claim of an ID token as the session subject only when the same
token carries `"email_verified": true`. An unverified email and a missing `email_verified` claim
fall back to `sub`. An `email_verified` that is not a JSON boolean (the string `"true"` included)
refuses the sign-in as a malformed token. The subject is what `ZS_CONTROL_ADMINS` and the dashboard member check
match, so an IdP that lets a user set an unverified email must not be able to pick the
subject. An IdP that never sends `email_verified`, such as Microsoft Entra ID by default, signs
in by `sub`, and the operator lists `sub` values.

**A dashboard session lasts 8 hours from sign-in, enforced by the server, and is stored hashed
(D4).** The control plane refuses a session whose row is older than 8 hours, whatever the
browser still sends, and deletes expired rows on the next sign-in; the cookie `Max-Age` is the
same value. It stores the SHA-256 of the cookie value as the session key, in `sessions` and
`csrf_tokens`, so a read of the database does not yield a usable cookie. There is no sliding
renewal. The migration that introduced the hashing ended every existing dashboard session.

**Tenancy is a boundary the control plane enforces, in two nested scopes.** Organization
carries the isolation property: policy, grants, audit and revocation are all
organization-scoped, and every `/wire/*` route denies cross-tenant access. Project
subdivides an already-isolated tenant (ADR-0021) and narrows further within it.

Both are read from the **device's enrolment row** — never from the request body, and never
from the client certificate's `O=` field. The body is the caller's own claim; a certificate
is real evidence but can outlive a device being moved. The enrolment row is written once,
from an operator token or from a self-enrolment token after an SSO sign-in (ADR-0036), and is
the single authority. The grant subject comes from the same row (§3).

An unscoped query here does not fail loudly — **it serves one tenant's data to another** —
which is why `cross_org.rs` and `cross_project.rs` test every route separately rather than
letting one test stand in for the set.

## 2. What ZeroSecret defends against

- A credential leaking through a committed `.env`, a shell history, a screenshot, or a
  chat paste.
- A coding agent reading credentials out of its own environment, process memory, or the
  files it can access.
- A developer keeping a working production credential after leaving the team.
- Credential reuse across workloads that should have different authority.
- An unaudited use of a shared credential.
- A compromised dependency in the workspace exfiltrating a long-lived key.

## 3. What ZeroSecret does not defend against

Stated plainly, because reviewers will find these anyway.

**A hostile local process of the same OS user.** The agent's listeners bind to a loopback
address only (`--listen` refuses any other address), and every local listener authenticates its
caller (ADR-0052): the HTTP proxy requires the run token in `Proxy-Authorization`, the local
endpoint and `/.zs/presign` require it as the first path segment, and the database listeners
close a connection whose peer socket belongs to another OS user. A process of the developer's own
user can read the token from the child's environment and passes the peer check, so it gets the
same access the developer has: the boundary is the OS user, not the process. On Windows the
database listeners do not check the peer, so there any local account that can reach a database
port is served; the proxy and the endpoint still refuse it. ZeroSecret converts
credential theft into session abuse. That is a real reduction — a stolen session expires
and is attributable — but it is not isolation. For an `aws_ssm` source, such a process can
also ask for a grant as the device and give its identity token to STS and SSM itself, with
no session policy. For this source it gets the value itself. A file store or a Vault token
has the same exposure on the agent; only resource-side materialization (the v2 gateway)
removes it. The workspace's own processes and coding agents still never get the value, the
token or the AWS session keys.

**Data exfiltration through an authorized path.** If alice may `GET` from Stripe,
ZeroSecret does not stop her, or her coding agent, reading and forwarding that data.
Authorization is not DLP.

**A body echo found after the head is sent truncates the response.** The agent sends an
injected response's head before it reads the body, so when the body echoes the credential
(§4 rule 9) the agent ends the response and the workload sees a truncated response, not a
502, with the bytes before the echo already delivered.

**The echo guard matches exact bytes.** The HTTP guard (§4 rule 9) matches the credential
raw and percent-encoded, and injected values as sent. The WebSocket guard (§4 rule 8) matches
the credential's raw bytes in the message stream. An upstream that returns the credential
JSON-escaped (`\/` for `/`, a `\u` escape), base64-encoded, percent-encoded inside a
WebSocket frame, or otherwise transformed is not matched. A credential made only of letters,
digits, `-`, `_`, `.`, `+` and `=` has one JSON form, so this matters for a credential with
`/` or a non-ASCII byte.

**No cap on concurrent connections, and one body clone per attempt.** Any local process can
open many connections to the agent's listener. The agent bounds a request head in 30 s and a
client TLS handshake in 10 s, but it does not cap the number of connections. An upstream
request body is cloned once for each attempt, two at most. An upgraded WebSocket session has
no data-frame deadline: a peer that declares a frame and then stalls holds the task until the
peer closes, or, when the session carries an injected credential, until the grant is revoked or
expires.

**Malicious code on the agent host.** Root, kernel, or EDR-level compromise defeats the
agent. ZeroSecret is not a sandbox.

**Revocation faster than the refresh interval.** A grant is verified offline, so a
revocation cannot reach an agent until it next contacts the control plane. `POST
/wire/revoke` records the withdrawal immediately and durably; the agent learns of it when
it next calls `GET /wire/revocations` and refuses the grant from that moment, before its
own expiry. An open WebSocket session that carries an injected credential, a header-scheme
session (`bearer`, `basic`, `api-key-header`) included, is checked again every 5 s: it ends
within 5 s of a revocation that the agent has learned of, or of grant expiry. The workload
gets a Close frame with code 1008 (or the connection drops if a frame was partly written),
and the agent audits `deny` `websocket revoked` (§7 row 91).

**The bound is the refresh interval, not the grant TTL.** Revocation does not wait for a
grant to expire — that is the distinction between revocation and expiry, and it is why
shortening TTLs is not a substitute. The fetch runs on its own 60 s timer, separately from grant renewal, so a slow renewal cannot
delay it.
An agent that cannot reach the control plane keeps
using cached grants until they expire (SECURITY §7 row 5), so an unreachable agent's worst
case remains one TTL.

**Revocations are served for 660 s and need standing.** `GET /wire/revocations` returns
only the last 660 s of revocations: two 300 s grant lifetimes plus 60 s of clock skew. An
older row cannot affect a live grant, and the list stays bounded. `POST /wire/revoke` needs
a live enrolment with a subject and a current membership of the device's organization; a
caller without them is refused and writes no row.

This is a deliberate trade for availability and latency: a per-request revocation check
would put the control plane in the path of every data-plane request, break ADR-0004's
offline verification, and make a control-plane outage a total outage. ADR-0018.

**Workload identity spoofing in v1.** `zs run --as claude-code` is a declared label. A
process on the same machine can claim a different label. Cryptographic workload identity
is roadmap work, not a v1 claim.

**Traffic that does not cross an interception layer.** A process started outside `zs run`
that ignores `HTTPS_PROXY` is not intercepted. It also gets no credential, so it fails
rather than leaking — but the developer experience is a failure, not silent protection.

**The login code does not stop a user who ignores it.** An attacker can start `zs login` on
their own machine and send the sign-in URL to a member. If the member signs in and confirms,
the attacker's `zs login` has the verifier, claims the self-enrolment token and enrols a device
as that member. The callback page shows `code <CODE> for device <NAME>` and a confirm button,
and `zs login` prints the same code and device name. The sign-in completes only after one click
on that button. The click must carry the `zs_login_confirm` cookie, which binds it to the browser
that completed the IdP sign-in, and a hidden value from the confirm page itself, so another page
cannot submit it and following the link alone enrols nothing. The CLI callback creates
no dashboard session. Only a member who compares the page with their own `zs login` output
before the click sees the attack. A pending login lives 10 minutes after `zs login` starts it.
ADR-0036 accepts this limit. The attacker's device is an ordinary self-enrolled
device, so the project, expiry and revocation bounds in ADR-0036 "Consequences" apply to it.
The dashboard ends a session only through `POST /logout`, which needs the session's CSRF token, so
a `GET /logout` signs nobody out. Sign-in uses PKCE: the authorize request carries an S256
challenge and the callback redeems the code with the verifier stored with the pending login.

**Committed run settings are as trusted as the repository.** `zs run` and `zs login` read the
`run` block of `zs-policy.json`, and an app repository commits that file. The repository also
supplies the command that `zs run` starts as the user, and that command can read every file
that the user can read. Do not run a repository that you do not trust under `zs run`. Inside
that boundary, these rules limit what a committed change can do:

- A stored enrolment is used only for the exact control URL that `zs login` enrolled with.
  Another URL gives `zs: not enrolled with <url>; run zs login`, not a new enrolment or a grant.
- A configured control CA whose SHA-256 differs from the hash stored at enrolment stops the run
  with `zs: control plane CA changed; run zs login`.
- A `credentials_dir` from the file must be strictly below `$HOME/.zs-credentials/` after `~/`
  expansion, and must have no `..` component. A `--credentials-dir` flag can name any directory.
- With a control URL, a policy file whose `signing_keys` or `grants` is not empty stops the run,
  on both paths. So the control plane is the only source of grants (ADR-0037).
- Each grant names its host. A binding whose `host` or `protocol` is not the grant's stops the
  run at startup (ADR-0037).
- Each grant names the upstream connection: `upstream_host`, `upstream_port`, the TLS mode as
  `upstream_tls`, and `local_endpoint`. On both paths, a binding field that differs from the
  signed value stops the run at startup, and a field the file leaves out takes the signed value
  (ADR-0038).

With a control plane, these rules together mean that a committed binding cannot get a
credential through a host, a port, a TLS mode, a CA, a pinned leaf or a local endpoint that the
control plane did not sign. A binding with no startup grant keeps its file values, so it may
open its file-chosen local endpoint. Every request through that endpoint that needs the
credential is denied for lack of a grant (`materialize` calls `authorized`,
`apps/zs/src/lib.rs:1055-1066`), and so is `POST /.zs/presign`. A request outside the binding's
`paths` is forwarded without a credential, as through the proxy (ADR-0027).

Local mode, with no control URL, trusts the signing keys and grants in the file by design, so a
committed file there can grant itself any host and any connection. A file with its own signing
keys or grants cannot also choose `credentials_dir`: the run stops unless the person passes
`--credentials-dir`.

Three limits remain. A `run.audit` or `run.ca_dir` from the file can point outside the
repository: only `credentials_dir` is limited, because the child command already runs the
repository's code as the user. `zs login` trusts the `control` and `control_ca` that the
settings name, so the user must check the line `zs: signing in to <control>` before signing
in. The third limit is the binding fields that the grant does not sign, below.

**A committed binding still chooses `auth` and the local-only fields.** The grant does not sign
these binding fields. `zs run` accepts them with a stored enrolment, with `--enrollment-token`
and in local mode:

- `auth` on an `https` or `http` binding. The scheme decides whether the raw secret goes on the
  wire (`bearer`, `basic`, `api-key-header`, `query-param`, `websocket-json-field`) or only a
  signature does (`aws-sigv4`, `hmac-body-signature`). The `header`, `param` or `field` decides
  where the secret goes. A `query-param` scheme puts the secret in the request URL, where
  upstream access logs can record it. The host, port and TLS mode are the signed ones. A `mongo`
  or `mysql` binding refuses a non-default `auth`. The owner accepted this limit on 2026-10-20.
  It can be signed later as one more field.
- `listen_port`. It is the local listener port on loopback. It never carries the credential off
  the machine.
- `paths`. It narrows where on the signed host the agent adds the credential. The grant's
  operations still bound every request.
- `user` and `auth_source` on a `mongo` binding. They name the account and the database for SCRAM
  to the signed host. SCRAM never sends the password.
- `user` on a `postgres` or `mysql` binding. It only narrows: the agent refuses a client that
  names another user. A binding without it lets the workload choose the role.
- `client_auth_plugin` on a `mysql` binding. It is the plugin between the local client and the
  agent. The upstream handshake does not change.

In local mode, the file signs its own grants, so the connection check runs against values the
file chose and protects nothing (ADR-0037, ADR-0038).

**A connection value is as strong as the dashboard `admin` role.** With a control plane, an
admin sets a resource's upstream host, port, TLS mode, CA SHA-256 and local endpoint in the
dashboard, and the control plane signs them (ADR-0038). Only an admin of the dashboard
organization can change them (ADR-0042). The only other path is the seed file on the control
host (`ZS_CONTROL_POLICY`), which `control` validates the same way. Such a change prints
`control: resource connection changed by <subject> resource="<name>"`, and a running `zs run`
applies it only after a restart. A connection change can:

- send the credential to another port of the granted host, where another service can listen;
- turn off upstream TLS where the rules allow `plaintext`: a `mongo` resource on any host, or an
  `https` resource whose upstream is loopback. SCRAM still never sends the MongoDB password, but
  the session crosses the network unencrypted (below);
- add a CA (`ca-sha256`), or replace the name and chain checks with a leaf pin (`pin-sha256`), on
  a `mysql`, `postgres` or `mongo` resource. An attacker on the network path who has a
  certificate from that CA, or the pinned certificate's key, can then act as the server for the
  granted host name. A MySQL server inside TLS can get the password. A PostgreSQL or MongoDB
  server gets a SCRAM exchange, which allows offline password guessing, and the session. A
  signed CA is added on top of the bundled public roots, and the binding names the CA file;
- set the TLS mode of a `mysql` or `postgres` resource back to `default`. For a binding that
  names no CA and no pin, the plaintext fallback and the downgrade limits below for MySQL and
  PostgreSQL then apply again. A binding that still names one stops the run;
- turn on `local_endpoint` for an `https` resource. The agent then opens a loopback endpoint and
  sets `ZS_<RESOURCE>_URL`. On an `aws-sigv4` binding, that endpoint also answers
  `POST /.zs/presign`, and a presigned URL is a bearer token for at most 15 minutes (see the
  presigned URL limit below).

Where the paragraphs below say "set `upstream_ca` or `upstream_cert_sha256`", with a control
plane an admin also signs the matching `upstream_tls` mode. Without it, the run stops.

**The subject comes from the enrolment row.** The control plane writes the subject on the
device row at enrolment: the SSO subject for a self-enrolment, or the issuing operator's
subject for an operator token. `/wire/grant` refuses a body subject that differs from the row
(ADR-0036). `/wire/enroll` refuses an enrolment token whose subject is missing or empty, such
as a token issued before ADR-0036, with 401 `enrolment refused`. The token is consumed and no
device is enrolled. `/wire/grant` refuses a device row with no subject (`device_unknown`): a
device enrolled with such a token between the ADR-0036 deploy and 2026-10-20 has no subject
and must enrol again. The device's private keys prove the device, not the person at the
keyboard: a same-user process that reads the native record and `.zs-device.json` acts as that
subject until the enrolment expires or an admin deletes the device or removes the membership.
`/wire/audit` does not check the device standing: an expired device, or a device whose
member was removed, can still send audit records until an admin deletes the device.
`/wire/policy` and `/wire/revocations` apply the same standing checks as `/wire/grant` and
refuse with its `device_unknown`, `enrolment_expired` and `not_a_member` codes.

**Approvals are roadmap.** The control plane does not treat `approval:` specially: with no
such resource in the policy, a grant request for one is denied as an unknown resource and
writes nothing (ROADMAP v2).

**The control CA is the only trust anchor for sign-in and `/wire/*`.** `zs login` and the
`/wire/*` clients of `zs run` trust only the control CA, from `--control-ca`, `run.control_ca`
or `<ca-dir>/control-ca.crt`. Two of them that differ are refused. Neither command fetches the
CA from the control plane that it is about to trust. `zs login` refuses an `http://` control URL
before any request unless its host is `localhost`, an address in 127.0.0.0/8 or `::1`, because
the claim response carries a bearer token. A `wire_url` that is not `https` and not loopback
is refused. A TLS terminator in front of a remote control plane must chain to the control CA.

**The control plane's grant-signing key is a file.** `control` keeps it in
`ZS_CONTROL_CA_DIR`, beside the control CA key `control-ca.key` (ADR-0036 has the file rules).
A reader of that file can sign grants that every device enrolled with this control plane
accepts. Protect the directory as you protect the control CA key.

**The first dashboard admins come from the control host's environment.** `ZS_CONTROL_ADMINS`
names the subjects that `control` makes `admin` at startup (ADR-0042). A person who can set
environment variables for `control`, or who can write to its database, can make themselves an
admin. Protect both as you protect `ZS_CONTROL_CA_DIR`. The README section "Dashboard admins"
has the operator rules.

**A session subject is printed without a control-character check.** The IdP session subject
(the verified `email` claim, else `sub`) is printed in `control:` lines for refused and changed
dashboard writes. The member forms and `ZS_CONTROL_ADMINS` refuse control characters, but the
IdP value does not pass that rule. A hostile IdP value can add a line break to such a log line.
Treat the line text as data when you read it.

**MySQL on plaintext does not authenticate the server.** When a MySQL server does not offer
TLS, the agent answers its challenge with a scramble (ADR-0029). The scramble proves the
password to the server, but nothing proves the server to the agent. An active attacker on the
path can act as the server and take the session. The attacker does not get the password: the
agent sends the password itself only inside verified TLS. An observer who records a scramble
can test password guesses offline, so a brokered MySQL password must be long and random. An
attacker can also remove the TLS offer from the greeting. To stop that, set `upstream_ca` or
`upstream_cert_sha256`: the agent then refuses a server that does not offer TLS. A pinned
certificate skips the name, chain and validity-date checks. The TLS handshake still proves that
the server has the pinned certificate's private key.

**PostgreSQL on plaintext does not protect the session.** When a PostgreSQL server answers
`N` to the SSLRequest, and the binding sets neither `upstream_ca` nor `upstream_cert_sha256`,
the agent continues in plaintext (ADR-0030). SCRAM-SHA-256 does not send the password. But
every query and every result row crosses the network unencrypted. An observer who records the
SCRAM exchange can test password guesses offline, so a brokered PostgreSQL password must be
long and random. The agent does not use SCRAM channel binding, so an active attacker on the
path can relay the login to the real server and then read or change the session. An attacker
can also change the server's `S` to `N`. To stop that, set `upstream_ca` or
`upstream_cert_sha256`: the agent then refuses a server that answers `N`. A pinned
certificate skips the name, chain and validity-date checks, as for MySQL.

**MongoDB on plaintext does not protect the session.** A `mongo` binding with
`upstream_plaintext: true` connects without TLS (ADR-0031). SCRAM does not send the password.
But every command and every reply crosses the network unencrypted, and an observer who records
the SCRAM exchange can test password guesses offline, so a brokered MongoDB password must be
long and random. The agent does not use SCRAM channel binding, so an active attacker on the
path can relay the login to the real server and then read or change the session. An active
attacker can also forge `hosts` and `primary` in the `hello` reply
and send the agent to a host of their choice. That host gets the user name, the client metadata
and one SCRAM exchange, but never the password. A binding without `upstream_plaintext` uses
verified TLS and removes these risks.

**The brokered MongoDB user's roles limit the client.** The agent does not authorize single
commands (PRODUCT §3). A client under `zs run` can do everything that the brokered user's
roles allow. A user with user-administration roles can read the stored SCRAM keys of users
(`usersInfo` with `showCredentials`). Give the brokered user the least role that the app needs.

**The workload chooses the PostgreSQL or MySQL database and role unless `user` is bound.** The
agent sends the server the client's own startup packet or handshake response with the brokered
credential. The user, the database, the PostgreSQL startup options and the MySQL connection
attributes are the client's. A password that is valid for more than one role is valid for each
role that the client names. Set `user` on the binding: the agent then refuses a client that
names another user before it materializes the credential, with SQLSTATE `28000` or MySQL ERR
1045, and audits `deny` `connect`, reason `user mismatch` (§7). The refusal text never names the
user. `user` binds the role, not the database or the startup options. PostgreSQL `SET ROLE`
still reaches each role that the bound user is a member of. MySQL sends its greeting before the
client names a user, so on every MySQL binding, with or without `user`, the agent reads the
server greeting before any decision: every refused MySQL client (a policy denial or a user
mismatch) still opens one upstream connection, and the agent closes it before it sends a
handshake response. The
agent always refuses a PostgreSQL startup that carries the `replication` parameter, whatever its
value and whatever the binding says, and audits `deny` `connect`, reason `replication refused`.

**An http binding sends the credential in cleartext.** A binding with `protocol: "http"` opts
in to plaintext (ADR-0033). The agent adds the credential to a request that crosses the network
unencrypted, so anyone on the path can read and replay it. The agent refuses an `http://`
request to an https binding and an `https://` request to an http binding, so plaintext happens
only where a binding names it.

**A presigned URL outlives the grant for 15 minutes.** The local endpoint answers
`POST /.zs/presign` with a URL signed by the real secret (ADR-0035). Any process of the same
user can ask, as for the proxy. The agent checks the grant for the method and the binding's
path scope first, requires `X-Amz-Date` within 15 minutes of now, and caps `X-Amz-Expires` at
15 minutes. It also refuses a URL whose `X-Amz-Date` plus `X-Amz-Expires` is more than
15 minutes from now, so a date ahead of the clock cannot stretch the lifetime. After that, the URL is a bearer token: revoking the grant does not stop a URL
already issued, which is why the cap is fifteen minutes. The answer carries a signature, never
the secret. The endpoint refuses a request whose `Host` is not its own loopback address or
that has an `Origin` header, so a web page cannot reach it by DNS rebinding.

**The agent signs what the client sends.** For `aws-sigv4` and `hmac-body-signature`, the agent
signs the method, path, query and signed headers (and, for `hmac-body-signature`, the body) that the client
chose, within the grant and the path scope. This is the same session-abuse limit as the first
paragraph of this section. A request with no `Authorization` header goes to an `aws-sigv4`
host unchanged and unsigned.

**Hash state is not zeroized.** The SHA-1 and SHA-256 crates in `Cargo.lock` (`sha1` 0.10.7,
`sha2` 0.10.9, `digest` 0.10.7) do not zeroize their block buffers. Hasher state and finalize
copies can keep password-derived bytes in memory until other data overwrites them.

**Interception is cooperative, and a workload inside `zs run` can still leave unseen.**
The paragraph "Traffic that does not cross an interception layer" was written about processes started *outside* `zs run`, and it
understated the limit. A workload started *by* `zs run` that does not use the proxy is
equally unintercepted, and it is **not** guaranteed to fail: if it carries a credential of
its own — a `.env` file, an inherited variable, a hardcoded token — it reaches the network
with no audit record at all. That is a silent fail-open, not a visible failure.

Two concrete paths were found running acme, a real Node workload, at step 30:

| Client | Behaviour | Status |
|---|---|---|
| axios (any version) | Honours `HTTPS_PROXY`, sends absolute-URI, not `CONNECT` | Closed — the proxy accepts both forms |
| Node global `fetch` (undici) | Ignores `HTTPS_PROXY` entirely | Narrowed — `zs run` injects an undici dispatcher via `NODE_OPTIONS` |

The `fetch` remedy is **cooperative, not enforcing**. The preload runs before workload
code, so it covers the accidental case, which is the common one. A workload that calls
`setGlobalDispatcher` afterwards, unsets `NODE_OPTIONS`, or spawns a grandchild that
strips it, opts back out — and so can any client that simply ignores the proxy variables.

**v1 does not claim to confine a workload that is trying to escape.** Enforcing egress
needs a network-level control — a sandbox, a netns, a firewall default-deny — which is
roadmap work. What v1 claims is narrower and still worth having: a credential the
workload never holds cannot be exfiltrated by a workload that leaves unintercepted.

**That sentence is the bound on PRODUCT §7's strict-mode claim**, which §7 defines as *the
workload gets access without receiving the upstream credential* and scopes to an intercepted
path (ADR-0022). The two fit together: an unintercepted workload receives no credential, so
the strict claim survives — what it does not receive is *access*, so it fails. §7 adds no
limit this section does not already state.

**A PostgreSQL protocol 3.2 CancelRequest is not relayed.** The relay accepts a CancelRequest
only in the 16-byte form, with a 4-byte process ID and a 4-byte secret key. Protocol 3.2 allows
a secret key of 4 to 256 bytes, so a 3.2 CancelRequest is classified as `Startup::Closed` and
dropped before any upstream contact. The drop is fail-closed, but a 3.2 client cannot cancel a
query through the relay. This path is not validated against PostgreSQL 18: the test compose
file and this machine provide PostgreSQL 16 and psql 15 only.

## 4. Credential handling rules

These are enforced in code review and in CI, not by convention.

1. A credential value exists only inside the data plane, only after grant verification,
   and only for the life of one protocol exchange. One exception (ADR-0041): a value read
   from an `aws_ssm` source stays in agent memory for the life of its grant, and at most
   300 seconds after the read, so the next connection does not call STS and SSM again. A
   timer drops it at that limit, even when no connection follows. A revocation drops it at
   once. A renewal with a changed source drops it and is skipped (ADR-0038), so the old
   grant still reads its old source until that grant expires. Rule 4 still applies.
2. Credential types do not implement `Debug`, `Display`, or `Serialize`. They zeroize on
   drop. In Go, the equivalent type's `String`, `GoString`, `Format` and `LogValue` print
   `[redacted]`, and its `MarshalJSON` returns an error.
3. No credential value reaches a log line, an audit record, an error message, a metric
   label, a panic payload, or a core dump.
4. No credential value is written to disk. Ever. Including cache, including swap-prone
   long-lived buffers where the platform allows locking.
5. Raw wire content — SQL text, request bodies, headers — never reaches an audit record.
   Audit stores decisions and metadata.
6. A grant carries a credential reference. Never a value.
7. The diagnostic log follows rules 3 and 5 (ADR-0028). `zs-diag` takes typed values only. A
   request path, a query string, a header value, SQL text, a body, argv after argv[0], an
   environment value and the subject are never logged. Server error text is kept only when it does not contain the credential.
8. No credential value reaches the workload. The agent holds each WebSocket data message from
   the upstream until its last fragment, and checks every data message and control frame before
   it writes it. One that carries the credential ends the session unseen (audit `deny`
   `websocket message`, reason `websocket echo`, ADR-0034). No 8-byte window of the credential
   (the whole credential when it is shorter) ever reaches the workload: before writing any
   payload taken from an upstream frame, the agent checks the bytes about to go out together
   with the last 7 payload bytes already written, and ends the session with nothing more
   written if they contain such a window. Frame headers and the agent's own Close frame carry
   no payload from the upstream and are outside that check. While the data
   tail ends with 8 or more bytes of the credential's start (half the credential if it is
   shorter than 16 bytes), the agent holds whole messages: a
   credential split across separate messages ends the session before any held message is
   written, a held message that would expose an 8-byte window is never written, and a held
   message is never written if the upstream ends or is quiet for 5 s (reason `websocket
   withheld`). A control frame cannot be held and does not release a held message; its payload
   is checked the same way, so a Close reason that carries a fragment behind its status code
   ends the session too. An upstream Close ends the session once it is written: no later frame
   is read and held messages are dropped (reason `websocket withheld`). A signing scheme gives
   the workload a signature, never the secret (ADR-0035).
9. An injected response whose head carries the credential (raw, percent-encoded, or an
   injected header or query value) is refused with 502 and audited `deny` `response echo`.
   `TRACE` is refused on an injected binding. The head check covers every header name and
   value and the reason phrase, and runs before any byte of the response reaches the
   workload, on the upgrade answer of a WebSocket binding too. An injected header or query
   value shorter than 8 bytes, `Host`, `Accept-Encoding`, and every `x-amz-*` header except
   `x-amz-security-token` are not matched. When an injected value is `<scheme> <token>`
   (`Basic …`, `Bearer …`), a token of 8 bytes or more is also matched alone. An injected
   request asks the upstream for `Accept-Encoding: identity`. A response with any other
   `Content-Encoding` is refused with 502 and audited `deny` `response encoded`, because its
   body cannot be scanned. The body and its trailers are checked as a stream: the agent holds
   back only the end of a chunk that is the start of a matched value, so a value split across
   chunks is seen whole, and releases the other bytes at once. A body that carries a matched value, or that ends with
   8 or more bytes of the start of one, is cut and audited `deny` `response echo` (§3). A WebSocket
   binding's refused upgrade answer gets the same checks. A copy of the credential that is
   transformed, or that has other bytes between its parts, is not matched.
10. Four inputs from outside the agent fail closed. A PostgreSQL SCRAM challenge with fewer
    than 4096 or more than 1,000,000 iterations is refused. The MySQL listener never offers
    `CLIENT_LOCAL_FILES` upstream: it is removed from the greeting and from the response the
    agent forwards, so a server cannot start a `LOCAL INFILE` transfer through the agent. A
    `file` credential reference resolves only when every part of its path is a plain name, so
    a drive prefix, a root, or a `.` part is refused as not resolvable. `zs run` with
    `--enrollment-token` applies the control URL rule (`https`, or `http` for a loopback host)
    to `--control` and to `--enroll-url` before it opens any connection.

**A policy evaluation that does not allow denies.** `zs-policy` evaluates every request with the
Cedar engine over a fixed policy set (ADR-0040). `Ok` requires an explicit allow, no diagnostic
error from the engine, and a resource the policy names. An engine error, an unknown resource, or
a missing allow returns `PolicyDenied`, and materialization never runs.

Rules 1 and 4 govern credential values: the upstream credentials that the agent
materializes for a verified grant. Rule 4 has no exception for them. The agent's local CA
private key is not an upstream credential. It lives for the whole agent run, so rule 1
cannot apply to it, and §6 governs where it is stored. §6 does not weaken rule 4: the
shipped agent writes no CA private key file, and it keeps the key only in the platform's
native secure store. Rules 2 and 3 apply to the CA key's storage path, with the memory limit
that §6 names.

## 5. Audit

Append-only and per-organization, written in two places with deliberately different shapes.

**The agent's local journal is hash-chained.** Each record carries `seq`, subject, workload
label, resource, protocol, operation, decision, reason, timestamp, and the `prev_hash`/`hash`
pair that makes an edit detectable. Each line is `sync_all`'d **before the decision
proceeds**, so a record cannot be lost by a crash that still let the request through. On Unix
the agent creates a new journal with mode 0600. A journal that already exists keeps the mode
it has; the agent does not change it.

**A torn last journal line is repaired, never trusted.** Each append writes one line and then
`sync_all`s it, so a crash between the two leaves a partial line. On the next start the agent
verifies every complete record in order, truncates a final line that ends without a newline,
and appends from the last complete record. The dropped bytes carry no `seq` and no `hash`, so
no record depends on them. A corrupt line that does end with a newline still fails closed, and
`zs-verify` reports a torn journal as broken until the agent repairs it. A repair outside the
agent is the same truncation: remove the bytes after the last `0x0a` byte, and never edit or
reorder a complete line. The journal is read for shipping on a blocking thread, not on a
runtime worker, so its size cannot stall request handling.

**A deny record says why (ADR-0032).** `operation` names the action: the request method,
`connect`, or a protocol operation. A NUL byte in `operation`, `reason` or `credential_ref` is
replaced with U+FFFD before the record is hashed, so a control character the ingest database
refuses cannot stop later records from shipping. The recorded resource is the authority's host
without any userinfo: a request target that carries `user:password@` is parsed down to its host,
and the diagnostic log withholds that destination. `reason` is set on deny records only. It holds text the
agent makes: a grant or policy reason, a refusal rule code, or a fixed text. It never holds
an upstream message or request content. It is part of the hash chain.

**The control plane's trail is the central one**, and the agent ships to it — periodically
while running, and once more as it exits (2026-09-17). Shipped records carry the enrolled
`device_id`, from which the control plane reads tenancy, and the journal's own `seq` and
`hash` fields, so an ingested record can be matched to the local chain. The control plane
does not maintain that chain across the two stores; the fields are carried, not verified
against a second chain. Tenancy, device and subject come from the client certificate and the
device row; a record's body subject that differs from the device row is kept as
`claimed_subject`.

**Shipping resumes from a persisted cursor.** The agent stores the highest accepted `seq`
in `<journal>.shipped` beside the journal, written atomically and with mode 0600. It advances
the cursor only after the control plane accepts a batch, so a refused or unreachable batch is
retried from the last accepted record instead of lost. Each ingest request carries at most
1 MiB of serialized ingest records; one record larger than the cap ships alone rather than
being dropped. The cap measures those ingest records, which carry `seq` and `hash` but not
`prev_hash`, so the journal lines behind one request can exceed 1 MiB. The cursor belongs to
the workspace, not to a device: a workspace re-pointed at another control deployment ships
its backlog under its next enrolment there, and the ingested records carry that device's
attribution.

**Signals do not cut the final ship short when the handlers install.** While the child runs,
`zs` forwards `SIGTERM` and `SIGHUP` to it. It does not forward `SIGINT`, because the terminal
already delivered that signal to the child's process group when it delivered it to `zs`. `zs`
keeps waiting for the child to exit, so the final ship runs before `zs` exits. A child that
traps the forwarded signal can exit with its own code; a child that does not trap it dies from
the signal, and `zs` still ships. If the signal handlers do not install, `zs` writes a fixed
line naming the failure to stderr and waits without forwarding; on that path a signal can
still kill `zs` and skip the final ship. The handlers stay registered for the rest of the
process, so after the child exits `SIGINT`, `SIGTERM` and `SIGHUP` are swallowed until `zs`
exits; a long final ship can then be stopped only by a signal the agent does not handle
(`SIGKILL`, `SIGQUIT`, `SIGABRT`).

Corrected 2026-09-17: this section previously claimed each record carries **policy version,
grant id, and agent id**. None of the three is in `zs_audit::AuditRecord` or in
`zs_wire::AuditIngestRecord`. Grant id in particular reads as though the trail could be
joined to a revocation (ADR-0018 keys revocation by grant id) — it cannot. Adding the field
is a reasonable v2 item; claiming it while absent is the drift PRODUCT §7 exists to stop.

**Both interception paths record.** Until 2026-09-17 the journal reached the HTTP proxy and
nothing else, so an L3 PostgreSQL session — an authenticated connection to a real database —
left **no audit record at all**. The decision is now written in the materialize step, before
the connection is relayed, so the rule below holds for L3 as it always did for HTTP.

**A path outside a binding's scope is recorded as a passthrough (ADR-0027).** On a binding
with `paths`, the agent forwards an out-of-scope request without a credential. Before it
forwards the request, it writes `passthrough` with the request method. An `allow` record
with operation `connect` records that the agent terminates TLS for a host. It does not
record a credential release. Only an `allow` record with a method records a release. No
record carries the request path, because a path can contain personal data or a token.

**The diagnostic log is not an audit record (ADR-0028).** The audit journal is the security
record. It is hash-chained, and it fails closed. The diagnostic log in `.zs-log` is a
best-effort debugging record. It carries no authority, it can lose events, and its
`audit_seq` field only points to the journal.

Unavailable audit sink means deny. An action ZeroSecret cannot record is an action
ZeroSecret does not authorize. For L3 that is literal: if the journal write fails, the
connection is refused rather than relayed unrecorded.

## 6. TLS and the local CA

The agent generates a local root CA on first run. Its private key stays in the platform's
native secure store, is never exported, is never shared between machines, and is never
issued by ZeroSecret's infrastructure. The CA signs only for hosts that match a configured
resource.

A new root is named `CN=ZeroSecret local CA`, signs only end-entity certificates (path length
0, key usages `keyCertSign` and `cRLSign`), and is valid from 5 minutes before it is created
for 10 years. A root that an earlier release created keeps its own name and validity and is
not replaced. Each leaf names its host in lowercase, is valid from 5 minutes before it is
minted for 24 hours, and is reused for at most 12 hours.

The agent modifies no trust store. `zs run` points the child at `ca.crt` through
`NODE_EXTRA_CA_CERTS`, which adds to Node's roots. `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
`CURL_CA_BUNDLE` replace a client's roots, and a passthrough host presents its real
certificate, so these three name `ca-bundle.crt`: `ca.crt` followed by the roots that the
parent's `SSL_CERT_FILE` or the system bundle holds (ADR-0035). If no bundle is found, they
name `ca.crt` and passthrough hosts fail TLS for those clients. The trust reaches only the
child and the descendants that keep that environment. `zs ca retire` deletes `ca-bundle.crt`
with `ca.crt`. `zs doctor` reports the CA directory and whether `ca.crt` exists.

**The CA private key lives only in native secure storage (ADR-0023).** The key signs a
certificate for every host the agent intercepts, so a readable copy is a copy of the
agent's whole interception authority. The certificate `ca.crt` stays on disk, because it is
public and trust stores need it.

| Platform | Native store | Record | The only "absent" result |
|---|---|---|---|
| macOS | Default keychain for writes; reads and deletes search the user's keychain search list. All through `/usr/bin/security` | Generic password: service `zerosecret.ca.v1`, account from `.ca-storage-id`, value `zsca1:<base64 record>` | Exit status 44 (`errSecItemNotFound`) |
| Linux | Secret Service default collection, over a Diffie-Hellman-encrypted D-Bus session | Item with attributes `service=zerosecret.ca.v1`, `account=<id>`, `schema=1` | A search with no unlocked and no locked match |
| Windows | Credential Manager | Generic credential, target `zerosecret.ca.v1/<id>`, persistence `CRED_PERSIST_LOCAL_MACHINE` | `ERROR_NOT_FOUND` |
| Any other OS | None | None | None. Startup fails with `secure CA storage unsupported` before the child starts |

The record is a versioned binary record of at most 2,560 bytes. It holds the certificate
PEM and the key PEM. `.ca-storage-id` holds a random 128-bit account ID as 32 hex digits.
It is public metadata: it names the record and is not a secret. An OS exclusive lock on
`.ca-storage.lock` serializes cooperating processes. A held lock fails at once with `CA
storage busy`. `zs run` never deletes a record; only `zs ca retire` does, as below. The
agent writes a record only after it reads that none exists. On macOS the write is natively create-only: `add-generic-password` without
`-U` fails when the item exists. Linux and Windows have no native create-only write, so the
adapter reads for absence first, under the directory lock that serializes `zs` processes. A
writer outside that lock is a limit below.

On Linux the agent requires an unlocked default collection and uses a zero-second prompt
timeout. It never unlocks or creates a collection. Each load and retire first checks the
default collection, before the CA directory is created or locked: a locked one denies with
`secure CA storage locked`. A locked match or more than one match denies. macOS cannot apply that duplicate rule: `find-generic-password` returns the first
match in the keychain search list, so a second item with the same service and account in
another keychain of the list is not detected. On Windows a read accepts only a generic
`CRED_PERSIST_LOCAL_MACHINE` credential with a blob of 1 to 2,560 bytes. This is CA key
storage only. It is not a claim of full product support on Linux or Windows.

**There is no fallback.** Only an explicit native "absent" result permits a fresh CA.
Locked, denied, unavailable, ambiguous, malformed, oversized, mismatched and partial states
deny startup, and they change no key, certificate or record. A missing key behind an
existing `ca.crt` denies. The agent never mints a replacement root, because a new root
invalidates every client that trusts the old one.

The shipped agent has exactly one CA load: `LocalCa::load_or_create_secure`, in the CA
phase of `apps/zs/src/run.rs`. It runs before any listener, background task or child.
`LocalCa::load_or_create` writes `ca.key.pem`; it remains only for legacy test fixtures,
and no shipped path calls it. Every failure is a fixed message. No native or third-party
error text reaches it. The [README](../README.md#local-ca-storage) lists the messages and
the owner's recovery steps.

**Migration keeps the existing key, in a fixed order.** A legacy key is `ca.key.pem` on any
platform. On macOS it can also be the pre-record Keychain item whose account and service
are both `zerosecret-local-ca-<digest of the directory's canonical path>`. The agent looks
for that item only when the directory exists before the load. A directory that does not
exist yet has no certificate, so no legacy key can belong to it, and its load reads no
legacy Keychain item.
Earlier agents named the item before they created the directory, so every default first
run (`--ca-dir .zs-ca`) wrote one shared item under the digest of the text `.zs-ca`. That
item is tied to no single directory, and the agent neither reads nor deletes it. The
[README](../README.md#the-shared-keychain-item-of-the-default-zs-ca) shows its exact
removal.

1. Validate every legacy key against `ca.crt`. A legacy key without `ca.crt` denies with
   `CA legacy identity incomplete`. A mismatch denies.
2. Confirm native absence, then persist `.ca-storage-id`.
3. Write the record: natively create-only on macOS, and after the adapter's own absence
   read on Linux and Windows.
4. Read the record back, compare it byte for byte, decode it, and validate it against the
   public certificate.
5. Publish `ca.crt` if it is missing, or require it to match.
6. Delete `ca.key.pem`, then the exact macOS legacy item.

A failure stops at its step with every remaining key copy in place. The next start
continues from that state. A unique legacy key is never deleted before steps 3 to 5
succeed.

**Retire is the only record delete, and it is conditional (ADR-0024).** `zs ca retire
--ca-dir <dir> --yes` has no default directory and needs `--yes`. In order, it:

1. Checks the store's lock, as a load does. Requires `<dir>` to be a directory, not a
   symbolic link, then takes its lock.
2. Refuses with `CA migration incomplete` while `ca.key.pem` or the directory's macOS
   pre-record item, the one named by its canonical path, exists. A start migrates and
   removes them first.
3. Reads the account from `.ca-storage-id`, and `ca.crt` if it exists, then the record. A
   missing ID or record, or an invalid `ca.crt`, denies.
4. Decodes the record and validates it. If `ca.crt` exists, requires it to match the record.
5. Deletes exactly that record: `delete-generic-password -a <account> -s zerosecret.ca.v1`
   on macOS, the one unlocked matching item on Linux, and `CredDeleteW` on
   `zerosecret.ca.v1/<account>` on Windows. A Linux duplicate denies and deletes neither.
6. Requires the record to read as absent, then removes `ca.crt` and `.ca-storage-id`.
   The lock file and the directory stay.

A failure before step 5 changes nothing. A failed delete, or an absence read that fails or
finds the record, keeps both files. A retry then finishes the job or, if the record is
already gone, reports `CA private key missing`, and only the directory is left to delete. A
failed file removal can leave `.ca-storage-id` alone. A directory whose `.ca-storage-id`
was copied from another names the same record, so retiring either one deletes the key of
both.

**macOS `security(1)` behaviour, observed on GitHub `macos-latest`.** For reads, only exit
status 44 means missing. Every other read or write status, and any signal, gives the fixed
`secure CA storage unavailable`. The legacy delete maps any status except success,
including 44, to `CA legacy key removal failed`. Stderr is discarded unread. Every
`security` call is limited to 30 s by default; `ZS_KEYCHAIN_TIMEOUT_SECS` sets 1 to 300
whole seconds, and any other value denies with `CA storage timeout invalid` before any
`security` call. A call that is still running at its bound is killed and reaped, and the
operation fails with the fixed error of that step.

*A locked keychain is refused before any read or write.* Each load and retire first runs
`security show-keychain-info` on the default keychain, bounded to 5 s or to the per-call
bound if that is shorter. Exit 0 continues. Exit 36 (`errSecInteractionNotAllowed`), or a
check still running at its bound, denies with
`secure CA storage locked`. Every other status denies as unavailable. The check runs before
the CA directory is created or locked, so a refused start leaves nothing behind. The agent
waits at most that bound; the user unlocks the keychain and retries.

*Observed on GitHub `macos-latest` (run 36969175191):* on a locked keychain
`show-keychain-info` does not exit 36. It blocks until the 5 s bound kills it, so the
timeout is what denies. Every locked load and retire denied with `secure CA storage locked`
in about 5,000 ms, against 30 s per read or write before. On the unlocked keychain the
check passed in 16 ms. The call most likely waits on an unlock prompt, so on an attended
Mac a user who unlocks within the bound lets the start continue. That is not observed:
the runner shows no UI.

*A read or write can still meet a locked keychain.* The check covers the default keychain
at one moment. A keychain that locks after it, or another locked keychain in the search
list, makes a read or write wait on an unlock prompt until the per-call bound denies it. A
timed-out read or write fails before any key or certificate is replaced or deleted. In CI
a killed write did not land. If one ever does, the next start reads it back and validates
it against the certificate and any legacy key before use. A locked keychain still reports a
missing item as exit 44, so in that window a fresh directory can persist `.ca-storage-id`
before its create-only write denies. The next start reuses it under the same account.

*A locked keychain still allows deletes.* In CI, `delete-generic-password` on a locked
keychain returned success and removed the item (run 36752464799). The probe test accepts
either outcome, so this is observed behaviour, not a pinned guarantee. It is harmless to
the engine. Both of its deletes, the legacy item after migration and the record in retire,
run only after the same operation read the directory's record. The lock check refuses a
locked default keychain before that, and a keychain that locks later holds that read at
its unlock prompt until the bound denies it.

*The final legacy delete can time out after it deleted.* It runs only after this start read
and validated the directory's record, published `ca.crt` if it was missing, and removed any
file legacy key. On a first migration that read is the readback after the write; on a
retry it is the existing record. A timeout or failure there ends startup with `CA legacy key
removal failed`. The killed delete may or may not have removed the legacy item. Either way
the item was a validated copy of the key that the record holds, and the next start deletes
it if it remains.

**Limits that remain, recorded rather than implied.**

*Same-user boundary.* Native storage keeps the key out of the config directory and away
from other users, under the store's own protection. A process that runs as the same user
can still ask the store for the record: from a macOS keychain through `security`, from an
unlocked Secret Service collection, or from Credential Manager. §3 already concedes this
boundary.

*The record passes through a process argument on macOS.* The adapter writes with the
`security` CLI, so the `zsca1:` value, which encodes the private key, is briefly visible in
the argument list of that call. An attacker who can read another user's process arguments
can already read the keychain without a prompt, so this does not widen the boundary. But it
is not nothing. A native Keychain API adapter would remove it. Its adoption is deferred and
needs a separate owner decision. It would change the adapter, not the record or the
recovery contract.

*Native check and delete are not atomic.* No store here has compare-and-delete. The engine
validates the legacy item's value, or in retire the record, then deletes by exact name. If
a same-user process replaces that item between the two calls, the engine deletes the
replacement. This stays inside the same-user boundary.

*Linux and Windows check and write are not atomic.* The directory lock serializes `zs`
processes only. On Windows `CredWriteW` overwrites a credential with the same target. A
same-user process that creates `zerosecret.ca.v1/<id>` between the adapter's absence read
and its write loses that credential, and the readback then matches the agent's own record.
On Linux `create_item` does not replace an existing item, but a racing create can leave two
matching items. The next read then finds more than one match and denies. Both need a
same-user writer that is not `zs`, so both stay inside the same-user boundary.

*The parsed key in memory is not zeroized.* The storage types that carry the key,
`SecretBytes` and `CaRecord`, implement no `Debug`, `Display` or `Serialize`, and they
zeroize on drop. No key text reaches an error message or a log line, because every failure
is a fixed message. But `LocalCa` holds the key as an `rcgen::KeyPair` for the whole run,
and that value is not zeroized on drop. Copies that `rcgen` and `ring` make while they parse
the key are not zeroized either. So the key can be in a core dump or in swapped memory of
the agent. `LocalCa` implements no `Debug`. On Linux, `dbus-secret-service` does not
zeroize its Diffie-Hellman session key, its AES key, or the buffers it decrypts the record
into, so the record can stay in the agent's memory after it is read.

*Linux `zs` needs libdbus at load time.* The adapter links `libdbus-1.so.3` dynamically, so
the Linux `zs` binary does not load, for any subcommand, on a host without that library.
`control` does not link it.

*No secure erasure.* Deleting `ca.key.pem` unlinks the file. Its bytes can stay in free disk
blocks, backups and snapshots. A native delete makes no erasure promise either.

*A directory deleted without retire orphans its record.* `zs ca retire` removes a
directory's record before its files. A directory that is deleted another way leaves its
`zerosecret.ca.v1` record behind, on all three platforms, and retire cannot name it once
`.ca-storage-id` is gone. On macOS the item comment names the canonical directory, for
information only; nothing deletes by it. Pre-record `zerosecret-local-ca-*` items of
deleted directories stay too. The owner removes an orphan by its exact name, as the
[README](../README.md#local-ca-storage) shows.

This cost is known. By 2026-09-17, 4,698 path-derived items had accumulated on one Mac,
agent startup had slowed from ~0.1 s to **1.4 s**, and every stale key stayed usable for
minting certificates: **a key that outlives its purpose is a key nobody is deciding to
keep.** macOS then pruned such items automatically until K2 removed that pruning on
2026-09-30. The pruning enumerated the default keychain and deleted items whose owner
directory no longer existed. That existence check and the delete cannot be atomic, so a
directory recreated between them lost a live key, and the next start minted a new root. The
load path now deletes exactly one item: the directory's own validated legacy item. Nothing
else is enumerated or deleted. Automatic cleanup stays open until an approved
conditional-delete design exists. A check-then-delete race is not an acceptable substitute.

Anything that starts agents against fresh directories adds records to the store it runs
against. The `zs-mitm` Keychain tests and the macOS `platform_ca_startup` tests refuse to
run outside a disposable CI keychain. The Linux native tests start a private session bus
and keyring, and the Windows native tests name exact random targets. The agent-spawning
`apps/zs` test harness (`TestHome`) deletes the exact record named by each test's
`.ca-storage-id` from the store the agent reached: on macOS the `zerosecret.ca.v1` item
through `security`, on Linux the item with exactly the record attributes on the inherited
session bus through `dbus-send`, and on Windows the generic credential
`zerosecret.ca.v1/<id>`. It fails the test if it cannot prove the record gone. CI counts
zero such items left in its disposable macOS keychain after the whole workspace suite, and
on a private Linux session bus after one agent-spawning test file. Windows CI exercises the
same cleanup in one ignored process test.

**The device identity uses the same native store (ADR-0036).** `zs login` keeps the TLS client
key and the device signing seed of an enrolment in one record, through the CA's adapters.
[ARCHITECTURE.md §4](ARCHITECTURE.md#device-enrolment-and-stored-identity) names the record
and the file. The write is create-only. A delete names the exact record. `zs logout` deletes
the exact records, `.zs-device.json` and `.zs-session`, and does not call the control plane,
so the device row stays until an admin deletes it or it expires. A store failure stops
`zs run` before any network call (§7). These limits apply:

*The same-user boundary and the macOS process argument.* The limits above for the CA record
apply to the device record too. A same-user process can read it from the store, and on macOS
the record value is briefly in the argument list of the `security` call that writes it.

*Linux and Windows device writes are check-then-create without a lock.* There is no directory
lock for the device record. Two `zs login` commands at the same time in one `ZS_HOME` are not
supported.

*`.zs-device.json` has no lock.* `zs login` and `zs logout` load the file, change it and save it
without a lock. When two of them run at the same time, one change can be lost.

**Upstream TLS settings are signed with a control plane (ADR-0038).** §3, "A connection value
is as strong as the dashboard `admin` role", owns who can change them, and "A committed binding
still chooses `auth` and the local-only fields" owns what stays unsigned.

## 7. Fail-closed matrix

A row marked `(commercial suite)` runs in `control/e2e`, the Go suite in the commercial
repository, against `control/bin/control`, the Go control plane (ADR-0049,
ADR-0051). Those rows move the control plane into its failure states through its process
interface and SQL; the binary named by `ZS_CONTROL_BIN` is what the suite starts.

| Condition | Result |
|---|---|
| Unknown destination | Pass through unmodified, no credential. Logged |
| Known resource, no grant | Deny |
| Grant expired | Deny. Attempt refresh |
| Grant signature invalid | Deny. Alert |
| Control plane unreachable, cache valid | Allow within cached grants |
| Control plane unreachable, cache expired | Deny |
| Audit sink unavailable | Deny |
| Materialization failed | Deny. Never fall back to a weaker path |
| Protocol implementation panicked | Deny that resource. Agent stays up |
| Grant revoked | Deny before expiry. Lag bounded by the refresh interval (ADR-0018) |
| Local CA storage locked, denied, unavailable, ambiguous, malformed or mismatched | Deny startup before any listener or child. Never mint a replacement CA (§6) |
| Grant revoked, then renewed | Deny. A renewal keeps each revoked grant's ID in the chain of the grant it replaced, for the last 32 renewals (ADR-0026) |
| Request method not in the grant | Deny that request. Audit the method (ADR-0026) |
| `https://` upstream on any port | TLS. Plaintext only by `upstream_plaintext` on a loopback upstream (ADR-0026) |
| A `Transfer-Encoding` other than exactly one `chunked`, conflicting `Content-Length` values, a body over 32 MiB, a head over 64 KiB, or a target carrying a fragment | Refuse the request. hyper reads the framing and refuses what it will not frame; the proxy refuses the codings hyper accepts and the fragment hyper would silently drop (ADR-0026, ADR-0039) |
| Request path outside a binding's `paths` | Forward without a credential. Keep the client's headers. No grant needed. Audit `passthrough` with the method (ADR-0027) |
| Ambiguous request target on a binding with `paths` | Refuse before the upstream. Audit `deny` with the method (ADR-0027) |
| `Host` missing, repeated or for another origin, or a target that is not origin-form, inside a tunnel to a bound host | Refuse before the upstream. Audit `deny` with the method. Absolute-form: the URI authority replaces `Host` (ADR-0027) |
| `paths` empty, not canonical or on a non-HTTPS binding, or an unknown binding field | Refuse the config at load. Never fall back to host-wide injection (ADR-0027) |
| Diagnostic log unavailable or full | Traffic continues. One stderr warning. The log never holds a credential, a request path or workload data (ADR-0028) |
| MySQL client sends `COM_CHANGE_USER` | Refuse with an ERR packet and close. Never forward it. Audit `deny` `change_user` (ADR-0029) |
| MySQL upstream asks for a method that sends the password without verified TLS, or switches to an unknown plugin | Refuse. Never send the password or the RSA key request (`0x02`) (ADR-0029) |
| MySQL upstream TLS fails verification or the pin, or `upstream_ca` or `upstream_cert_sha256` is set and the server does not offer TLS | Refuse. Never fall back to plaintext (ADR-0029) |
| MySQL client asks for TLS or compression on the loopback leg | Refuse before any auth data goes upstream (ADR-0029) |
| PostgreSQL upstream TLS fails verification or the pin | Refuse before the startup packet. Never fall back to plaintext (ADR-0030) |
| PostgreSQL binding sets `upstream_ca` or `upstream_cert_sha256`, and the server answers `N` to the SSLRequest | Refuse before the startup packet (ADR-0030) |
| PostgreSQL server sends a byte after `S` before the TLS handshake, or an answer that is not `S` or `N` | Refuse before the startup packet (ADR-0030) |
| MongoDB client sends `saslStart`, `saslContinue` or `authenticate` | Send an error reply (code 18, fixed text) and close. Never forward it. Audit `deny` `authenticate` (ADR-0031) |
| MongoDB client sends a first message that is not `hello`, `OP_COMPRESSED`, a checksummed message, a later `OP_QUERY`, another opcode, a frame outside the limits, or a frame that does not parse | Close. Never forward it (ADR-0031) |
| MongoDB upstream offers no SCRAM mechanism, or gives a bad nonce, an iteration count out of range, too many rounds or a wrong server signature | Refuse. Never relay (ADR-0031) |
| MongoDB upstream TLS fails verification or the pin | Refuse. Never fall back to plaintext (ADR-0031) |
| MongoDB discovery finds a primary that is not in `hosts`, needs a second redirect, finds another set name, or finds no writable primary | Refuse. Never authenticate there (ADR-0031) |
| Grant or resource lists `*` and the operation is `connect` | Deny. `*` names HTTP methods only (ADR-0033) |
| `http://` request to an https binding, or `https://` request to an http binding | Deny before the upstream. Audit `deny` (ADR-0033) |
| `upstream_plaintext` on an http binding | Refuse the config at load (ADR-0033) |
| WebSocket message (whole or in fragments) or control frame from the upstream carries the credential | End the session before it reaches the workload. Audit `deny` `websocket message`, reason `websocket echo` (ADR-0034) |
| WebSocket message over 32 MiB, masked server frame, or reserved bits set | End the session (ADR-0034) |
| `websocket-json-field` request without `Upgrade: websocket` | Deny (ADR-0034) |
| `aws-sigv4` request with `Authorization` but no valid `x-amz-date`, no `x-amz-content-sha256`, a malformed `STREAMING-` body or one carrying an unexpected trailer header, a missing signed header, or `host` not signed | Deny before the upstream (ADR-0035) |
| `aws-sigv4` request with no `Authorization` header | Forward unchanged. No credential is used (ADR-0035) |
| `hmac-body-signature` request without its `id_header` | Deny before the upstream (ADR-0046) |
| `/.zs/presign` for a method not in the grant, a path outside the scope, a non-https binding, signed headers other than `host`, an expiry outside 1 s to 15 minutes, or an `X-Amz-Date` more than 15 minutes from now | Deny. Audit `deny` `presign <METHOD>`. Never call upstream (ADR-0035) |
| Local endpoint request whose `Host` is not its loopback address, or that has an `Origin` header | Refuse before the upstream (ADR-0035) |
| Grant revoked or expired, or the audit write fails, during a WebSocket session | Refuse the next message that would carry the credential and end the session. Audit `deny` `websocket message` (ADR-0034) |
| Upstream WebSocket data messages or control frames that would put an 8-byte window of the credential (the whole credential when it is shorter) on the client stream, including a held prefix released by a later data message and a Close reason that carries a fragment behind its status code | End the session before that write; a held message is never released when it would expose such a window. A control frame does not release a held message. An upstream Close ends the session and no later frame is read; held messages are dropped. Audit `deny` `websocket message`, reason `websocket echo` or `websocket withheld` (ADR-0034) |
| `zs run` with a control URL, no `--enrollment-token`, and no enrolment for that URL in `.zs-device.json` | Stop before any network call and before the child: `zs: not enrolled with <url>; run zs login` (ADR-0036) |
| `.zs-device.json` has an enrolment for the control URL, but its native device record is missing | Stop before any network call: `zs: not enrolled with <url>; run zs login` (ADR-0036) |
| Native device record locked or unavailable | Stop before any network call: `zs: device record: secure storage locked` or `zs: device record: secure storage unavailable` (ADR-0036) |
| Configured control CA hash differs from the hash stored with the enrolment | Stop before any network call: `zs: control plane CA changed; run zs login` (ADR-0036) (commercial suite) |
| `--control-ca` or `run.control_ca` names a CA that differs from `<ca-dir>/control-ca.crt` | Stop before any network call. Use neither CA (ADR-0036) |
| Binding sets `upstream_host` with a stored enrolment | Start when it equals the signed `upstream_host` (ASCII case-insensitive). Otherwise stop before any listener and the child with the row 61 line (ADR-0038) (commercial suite) |
| `/wire/grant` answers 401 at startup, stored enrolment | Stop before the child: `zs: this device is no longer enrolled; run zs login` (ADR-0036) (commercial suite) |
| `/wire/grant` answers 401 at startup, `--enrollment-token` run | Stop before the child: `zs: control plane refused this device (<code>)` (ADR-0036) |
| Grant does not verify with the pinned key at startup, stored enrolment | Stop before the child: `zs: control plane signing key changed; run zs login` (ADR-0036) (commercial suite) |
| Grant `host` differs from the binding's `host` at startup | Stop before the child: `zs: <resource>: binding host does not match the grant` (ADR-0037) |
| Grant `protocol` differs from the binding's `protocol` at startup | Stop before the child: `zs: <resource>: binding host does not match the grant` (ADR-0037) |
| `zs login` with an `http://` control URL whose host is not loopback | Refuse before any request (ADR-0036) |
| `zs-policy.json` has a non-empty `signing_keys` or `grants`, and a control URL is set (`--control` or `run.control`, with or without `--enrollment-token`) | Stop before any network call and before the child: `zs: signing_keys and grants in the policy file are not allowed with a control plane`. The control plane is the only grant source. Local mode keeps file keys and grants (ADR-0037) |
| `/wire/grant` fails at startup with a transport error (connection refused, timeout, TLS failure) or an HTTP status of 500 or more, stored enrolment or `--enrollment-token` run | Stop before the child: `zs: control plane unavailable at <wire_url>; check the connection and retry`. The line does not repeat the error text. A 403 or 404 is a policy refusal and gives "Known resource, no grant" (ADR-0036) (commercial suite) |
| `zs-policy.json` has a non-empty `signing_keys` or `grants`, no control URL is set, and `credentials_dir` came from its `run` block (no `--credentials-dir` flag) | Stop before the child: `zs: a policy file with its own signing_keys or grants cannot choose credentials_dir; pass --credentials-dir`. A committed file cannot sign a grant and point at a credential directory of its own choice. A `run` block without `credentials_dir` is unchanged (ADR-0037) |
| A binding field the file sets (`upstream_host`, `upstream_port`, `upstream_plaintext: true`, `upstream_ca`, `upstream_cert_sha256`, `local_endpoint: true`) differs from the signed connection at startup, stored enrolment or `--enrollment-token` run | Stop before any listener and the child: `zs: <resource>: <field> is <file value> in the policy file, but the control plane signed <signed value>; remove <field> from the policy file, or ask an admin to change resource <resource>`. Hosts compare ASCII case-insensitively, pins as bytes. A field the file leaves out takes the signed value (ADR-0038) |
| The control plane signed `ca-sha256:<H>` and the binding's `upstream_ca` file hashes to another value, at startup | Stop before any listener and the child: `zs: <resource>: upstream_ca <path> has SHA-256 <file hex>, but the control plane signed <H>; restore the file, or, if the new file is intended, ask an admin to set the resource's CA SHA-256 to <file hex>`. The line never holds the file content (ADR-0038) |
| The control plane signed `ca-sha256:<H>` and the binding has no `upstream_ca`, at startup | Stop before any listener and the child: `zs: <resource>: the control plane signed a CA bundle with SHA-256 <H>; set upstream_ca to that file` (ADR-0038) |
| A renewed grant's connection (`upstream_host`, `upstream_port`, `upstream_tls`, `local_endpoint`) differs from the running binding's effective connection | Skip that renewal and keep the current grant until it expires: `zs: <resource>: the control plane changed <field> (signed <value>, running <value>); restart zs run to use it`. Diagnostic `renewal_failed`, failure `connection_mismatch` (ADR-0038) |
| A cached grant's connection differs from the binding's effective connection at a request, with a control plane or in local mode | Deny that request: `<resource>: <field> differs from the grant` (ADR-0038) |
| CONNECT or absolute-form request to an https or http binding's host on a port that is neither its effective `upstream_port` nor the protocol default (443, 80) | Deny: `port <n> is not the signed port <m>`. An allowed request forwards to the effective `upstream_host:upstream_port`, never to the requested port (ADR-0038) |
| `ZS_CONTROL_ADMINS` with an empty item or an invalid subject | `control` exits 1 before it listens: `control: ZS_CONTROL_ADMINS: item <n>: <reason>` (commercial suite) |
| Dashboard GET with no session, including `/audit` and `/export/audit` | 401, no org data in the body (commercial suite) |
| Dashboard membership or role lookup fails, or no database is configured | 503, nothing written or shown (commercial suite) |
| Dashboard POST with a session whose subject is a `member` | 403, nothing written (commercial suite) |
| Dashboard POST with a session whose subject is not a member of the dashboard org | 403, nothing written (commercial suite) |
| `POST /approvals/{id}/approve` with no session or no CSRF token | 401 or 403, flag unchanged (commercial suite) |
| Admin demoted while signed in; next POST from that session | 403 (commercial suite) |
| Demotion or removal of the last admin, by create, update, rename or delete | 400, row unchanged (commercial suite) |
| Demotion or removal of a `ZS_CONTROL_ADMINS` subject, by create, update, rename or delete | 400, row unchanged (commercial suite) |
| `/members/create` or `/members/update` with a role outside `admin`, `member` | 400, row unchanged (commercial suite) |
| `/enrollment-token` naming an org the subject is not a member of | 403, no token (commercial suite) |
| A grant with an `aws_ssm` source and no identity token | Deny: `materialization failed: no identity token`. No STS call (ADR-0041) |
| STS refuses the identity token (`AccessDenied`, `InvalidIdentityToken`, `ExpiredTokenException` or another code) | Deny: `materialization failed: aws_ssm refused`. The token is in no stdout, stderr, diagnostic or journal line, and in no file under `ZS_HOME`. The AWS code goes only to the diagnostic event |
| STS or SSM does not answer in 5 s, or cannot be reached | Deny: `materialization failed: aws_ssm timed out` or `materialization failed: aws_ssm unreachable` |
| SSM refuses the read (`ParameterNotFound`, `AccessDeniedException`, KMS access denied) | Deny: `materialization failed: aws_ssm refused`. The audit `credential_ref` is `aws_ssm:<role_arn>:<parameter>`; the text the workload sees names neither (ADR-0044) |
| The SSM value is empty or a `StringList` | Deny: `materialization failed: aws_ssm returned an unusable value` |
| The cached AWS session has expired and its refresh at STS fails | Deny: `materialization failed: aws_ssm refused`. The session is dropped; the next request asks STS again |
| A grant is revoked while its AWS session and value are cached | The agent drops both at once. The next request is denied as revoked and makes no AWS call |
| A local `zs-policy.json` holds a grant whose source is not `file`, or a binding with a `source` key | Stop before any listener and the child: `zs: policy: <resource>: a local grant may only use a file source`, or `zs: policy: <resource>: source is set only by the control plane` (ADR-0043) |
| Upstream response head to an injected request carries the credential, raw or percent-encoded, or an injected header or query value ≥ 8 bytes (a redirect `Location` included) | Refuse with 502 before any byte reaches the workload. Drop the response and its connection unread. Audit `deny` `response echo` (`apps/zs/tests/response_echo.rs`) |
| A WebSocket binding's upgrade answer carries the credential in its head | Refuse with 502. Audit `deny` `response echo` (`apps/zs/tests/websocket_binding.rs`) |
| `TRACE` request on an injected binding | Refuse with 502 before materialization; nothing reaches the upstream. Audit `deny` `trace refused` (`apps/zs/tests/response_echo.rs`) |
| Upstream response body or trailer to an injected request (a WebSocket binding's refused upgrade answer included) carries the credential, raw or percent-encoded, or an injected value ≥ 8 bytes, whole or split across chunks, or ends with 8 or more bytes of its start | Cut the response before those bytes reach the workload; the workload sees a truncated response. Audit `deny` `response echo` (`apps/zs/tests/response_echo.rs`, `apps/zs/tests/websocket_binding.rs`) |
| Upstream response to an injected request has a `Content-Encoding` other than `identity` | Refuse with 502 before any byte reaches the workload. Audit `deny` `response encoded` (`apps/zs/tests/response_echo.rs`, `apps/zs/tests/websocket_binding.rs`) |
| Grant revoked or expired during a WebSocket session that carries an injected credential, a header-scheme session that sends no credential in its messages included | End the session within 5 s of the agent learning of it: send the workload a Close frame with code 1008, or drop the connection if a frame was partly written. Audit `deny` `websocket message`, reason `websocket revoked` (`apps/zs/tests/revocation.rs`, `apps/zs/tests/fail_closed_matrix.rs` row 91) |
| PostgreSQL upstream SCRAM challenge has fewer than 4096 iterations | Refuse. Never derive a proof from it (`apps/zs/tests/fail_closed_matrix.rs`) |
| `/.zs/presign` URL whose `X-Amz-Date` plus `X-Amz-Expires` is more than 15 minutes from now, though each is within its own limit | Deny. Audit `deny` `presign <METHOD>`. Never call upstream (`apps/zs/tests/fail_closed_matrix.rs`) |
| MySQL client sets `CLIENT_LOCAL_FILES` | The agent clears it: the response forwarded to the server never carries it (`apps/zs/tests/fail_closed_matrix.rs`) |
| PostgreSQL startup or MySQL handshake names a user other than the binding's `user` | Refuse before materialization: PostgreSQL SQLSTATE `28000`, MySQL ERR 1045. The refusal text never names the user. Audit `deny` `connect`, reason `user mismatch`. PostgreSQL never connects upstream; MySQL reads the server greeting but never sends the server a handshake response (`apps/zs/tests/fail_closed_matrix.rs`) |
| PostgreSQL startup carries the `replication` parameter, whatever its value | Refuse with SQLSTATE `28000` before materialization and before any upstream connection. Audit `deny` `connect`, reason `replication refused` (`apps/zs/tests/fail_closed_matrix.rs`) |
| More than 30 requests in one minute from one TCP peer host to `/login`, `/login/callback`, `/login/confirm`, `/login/claim`, `/logout`, `/enrollment-token` and `/wire/enroll` together | The 31st and later get 429 `too many requests` before the handler runs, so no token is minted. The limit keys on the TCP peer address, never on `X-Forwarded-For`. `/healthz` and `/ca` are not limited (D11) (commercial suite) |
| A proxy request without the run token, or with another run's token | 407 `ZeroSecret needs the run token` with `Proxy-Authenticate: Basic realm="zs"`. No grant lookup, no audit record, no upstream contact. Diagnostic event `caller_refused`, `listener` `proxy` (`apps/zs/tests/fail_closed_matrix.rs` row 98) |
| `Proxy-Authorization` on a request the proxy forwards | Removed before the upstream request; the upstream never sees it (`apps/zs/tests/fail_closed_matrix.rs` row 99) |
| A local endpoint or `/.zs/presign` request whose path does not start with the run token | 403 `ZeroSecret needs the run token`. No upstream, no audit record. Diagnostic event `caller_refused`, `listener` `endpoint` (`apps/zs/tests/fail_closed_matrix.rs` row 100) |
| A database listener's peer lookup fails, finds no established socket of the agent's OS user for the connection, or runs on a platform with no lookup | Connection closed before any byte is read; no materialization, no upstream contact. Diagnostic event `caller_refused` (`apps/zs/tests/fail_closed_matrix.rs` row 101) |
| A database client whose OS user differs from the agent's (Linux, macOS) | Connection closed before any byte is read; no materialization, no upstream contact. Diagnostic event `caller_refused`. Windows database listeners do not check (§3) (`apps/zs/tests/fail_closed_matrix.rs` row 102, run in CI with a second OS user) |

Rows marked `(commercial suite)` run against the Go control plane: the binary built from
`control/`, driven as a process by the Go suite in `control/e2e` in the commercial repository
with `ZS_CONTROL_BIN` set to it. The Rust reference no longer exists (ADR-0049, ADR-0051).

At renewal, a 401, a transport error, a 5xx, a grant that does not verify, and a grant whose
`host`, `protocol` or connection differs do not stop the run. The agent prints one line and skips that renewal, so the binding keeps its
current grant only until that grant expires. A policy denial (403) for one binding at startup
does not stop the run either: the run starts, that binding has no grant, and its requests are
denied and audited, as for "Known resource, no grant".

Limit for the `aws_ssm` rows: the STS form body that the agent gives to reqwest, and
reqwest's own request and response buffers, are not zeroized. The identity token, the AWS
session keys and the SSM value can stay in freed agent memory until the memory is used again.

## 8. Open questions

Tracked here until answered, then moved into a decision.

- **v1 — local caller authentication.** Every local listener of `zs run` refuses a caller that
  is not a process of the OS user who runs it: the proxy and the endpoint check a per-run token,
  and the database listeners check the peer socket (ADR-0052). The ceiling is the OS user:
  a process of that user can read the run token from the child's environment and passes the peer
  check. It is not isolation. Windows database listeners do not check the peer (§3).
- **Deferred to v2.** Does the CI runner case need a different identity model than a
  developer workstation?
- **What is the correct grant TTL?** It trades revocation lag against control-plane load
  and offline tolerance. Still open as a *policy* question — an operator cannot configure
  it — but the v1 values are now measured rather than guessed, and this entry previously
  named the wrong one.

  | | Value | Where |
  |---|---|---|
  | Grant TTL | **5 minutes** | `wire_grant`, `expires_at_ms: now + 300_000` |
  | Revocation refresh | **60 seconds** | `REFRESH_SECONDS` in `apps/zs/src/main.rs` |

  Corrected 2026-09-17: this entry said v1 hardcodes **1 h**. It does not, and never did.
  The difference matters — TTL is the revocation bound for an agent that cannot reach the
  control plane (§3), so an overstated TTL overstates that window by a factor of twelve.
  Making it configurable is the v2 work; the number itself is no longer unknown.

## 9. Reporting a vulnerability

Report a vulnerability through GitHub private vulnerability reporting on the public
repository: open the **Security** tab and choose **Report a vulnerability**. Do not open a
public issue, pull request or discussion for it. A security email address does not exist yet;
until it does, GitHub's private reporting is the only channel (ADR-0045).

Include:

- the version or commit you tested;
- the platform, and the protocol or binding involved;
- the steps that reproduce the problem, with the smallest policy file that shows it;
- what you expected to happen and what happened, against the rule in this document it breaks
  (a row of §7, or a rule in §4), if you know it.

Never put a credential value in a report, a log excerpt or a reproduction. Replace each one
with a placeholder such as `<redacted>`. If a credential reached a log, a transcript or a
public place, rotate it first and report afterwards.

A report about a limit that §3 already documents is still useful when it shows the limit is
wider than §3 says.
