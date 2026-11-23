# ZeroSecret Architecture

**Status:** Approved direction
**Date:** 2026-09-05
**Owner of:** planes, crate layout, module contracts, data flow, budgets

> Product scope → [PRODUCT.md](PRODUCT.md)
> Threat model and documented limits → [SECURITY.md](SECURITY.md)

## 1. Planes

Four components. Three trust boundaries. Never one binary.

```mermaid
flowchart LR
    subgraph dev["Developer side"]
        WS["Workspace<br/>app · script · container · coding agent<br/>ZERO credential"]
        AG["ZeroSecret Agent<br/>identity · interception<br/>policy · materialization · injection"]
    end

    subgraph res["Resource side"]
        GW["Gateway (v2)<br/>private reach<br/>remote materialization"]
        R["Resource<br/>API · PostgreSQL"]
    end

    CP["Control Plane<br/>identity · orgs · policy<br/>resources · grants · audit"]

    WS -->|intercepted traffic| AG
    AG -->|direct| R
    AG -.->|tunnel, v2| GW
    GW --> R
    CP <-->|mTLS · signed grants| AG
```

**Workspace** — where application code runs. Zero credential access. No SDK. No
awareness that ZeroSecret exists.

**Agent** — runs at the *workload's network boundary*, not "on the laptop". Laptop, dev
VM, remote workspace, and CI runner are the same rule. The agent is never inside the
application container and never inside the project directory.

**Control plane** — issues identity, owns configuration, evaluates policy, mints signed
grants, ingests audit. It is a SaaS component operated by ZeroSecret.

**Gateway** — v2. Runs adjacent to a resource that the developer cannot reach directly.
Solves connectivity, and lets materialization happen on the resource side so the
credential never reaches the developer's machine at all.

**No gateway binary ships in v1.** There is no `apps/gateway` workspace member and nothing
in v1 builds or deploys one. An earlier prototype was quarantined to
a spike (not published) at step 25; its README names four defects that make it
unsuitable as a trust boundary, and v2 rebuilds rather than hardens it.

Materialization is a **capability**, not a binary. It runs at either trusted boundary.

## 2. Workspace

This repository is the open-source engine (ADR-0050), and the paths below start at its root.
The commercial layer — the Go control plane in `control/`, the dashboard, and its Go
end-to-end suite `control/e2e` — is a separate private repository, which pins a released
tag of this repository (ADR-0051). No commercial source file is tracked here.

```
crates/
  zs-vectors           golden vector files: one format, one index, one meta-check
  zs-identity          `Subject` and `WorkloadLabel`: the non-empty identity strings
  zs-diag              per-run diagnostic events: typed, best-effort, never a credential
  zs-credential        the credential types: `CredentialRef`, `Credential`, `IdentityToken`.
                       Provider adapters (Vault, OpenBao, AWS SM, GCP SM, 1Password) are roadmap
  zs-policy            the policy reference evaluator: Cedar over a fixed policy set (ADR-0040),
                       and `permits`, the operation check the agent runs on each request. The
                       control plane decides with `cedar-go` (ADR-0048 D3)
  zs-grant             signed grant: control mints, agent and gateway verify
  zs-protocol          protocol trait: match, authorize, inject. For the L3 listeners: the
                       accept gate, and the session check that travels with the credential
                       and ends an open session when its grant ends (ADR-0059)
  zs-upstream          upstream connect for the L3 listeners and zs-mitm; TLS verification and
                       leaf pin for the L3 listeners;
                       `http`: the one outbound HTTP client (rustls on ring, explicit timeouts,
                       no redirects, explicit proxy policy)
  zs-wire              control <-> agent JSON DTOs (ADR-0011)
  zs-proto-http        bearer, basic, api-key header, query param; `sigv4::sign` for AWS calls
  zs-proto-postgres    wire protocol, SCRAM, upstream TLS negotiation. The dynamic role is not implemented
  zs-proto-mysql       wire protocol, native and caching_sha2 auth, upstream TLS negotiation
  zs-proto-mongo       wire protocol, SCRAM-SHA-1/256, one-member replica set view, upstream TLS
  zs-proto-redis       RESP framing, `AUTH` and `HELLO AUTH` rewrite to the binding user and the
                       credential, upstream TLS (ADR-0057)
  zs-materializer      grant -> usable credential (retrieve; exchange is not implemented: the
                       agent wires `UnconfiguredExchange`, which refuses); `StoreRegistry`
                       routes the grant's source kind (`file`, `aws_ssm`) to one store and never
                       falls back; `SsmStore` reads AWS SSM through STS web identity;
                       `GrantBoundCache` keeps a value for its grant, at most 300 s
  zs-audit             append-only, hash-chained, redacting
  zs-mitm              local CA, certificate minting, TLS termination, HTTP/1 through hyper,
                       device record store
  zs-test-keychain     test-only: disposable macOS keychain interlock and exact cleanup
  zs-test-idp          test-only: fake OpenID Provider shared by control and zs tests
  zs-test-aws          test-only: fake STS and SSM with independent verifiers, p256 token signer
  zs-conformance       protocol conformance suite: cases, fake SigV4 upstream, report; no zs-* dependency

apps/
  zs                   CLI and agent daemon, one binary
```

The control plane is a separate Go module in `control/` in the commercial repository. It
serves the JSON wire API and the dashboard from one binary:

```
control/
  cmd/control          process entry: configuration, migration, listeners, shutdown
  internal/            one package per responsibility
  migrations/          the PostgreSQL schema
  vectors/             control-plane golden vectors
  css/                 the dashboard stylesheet
```

The process can open a third listener (`ZS_CONTROL_METRICS_ADDR`) that serves only
`GET /metrics`, and it can serve one organization per request host
(`ZS_CONTROL_ORGANIZATIONS`). The host is resolved before any dashboard or login handler runs;
`GET /healthz`, `GET /ca` and `POST /wire/enroll` answer on any host, because a load balancer
does not know the tenant and an enrolment token names its organization.

| Package | Owns |
|---|---|
| `internal/config` | environment and listener configuration |
| `internal/server` | `chi` routing, listener startup, mTLS, `GET /ca` |
| `internal/metrics` | the Prometheus text exposition and its own listener |
| `internal/tenant` | the organization selected by the request host, and its IdP |
| `internal/store` | PostgreSQL: `sqlc` queries, startup migration, per-run test schemas |
| `internal/wire` | `/wire/*` handlers and wire authorization |
| `internal/wake` | the `LISTEN zs_wire` connection and the hub for held `/wire/revocations` requests |
| `internal/session` | login, OIDC callback, logout, session authorization, CSRF |
| `internal/dashboard` | operator pages and mutations, `templ` templates and the stylesheet |
| `internal/policy` | `cedar-go` evaluation over the fixed policy set |
| `internal/grant` | canonical grant payload, Ed25519 signing |
| `internal/federation` | identity-token signing, JWKS, OIDC discovery |
| `internal/oidc` | relying-party client and ID-token verification |
| `internal/keyfile`, `internal/signing`, `internal/ca` | key material: 0600 key files, grant key, device CA |
| `internal/secret`, `internal/wirejson` | redacting secret types, the wire JSON codec |
| `internal/vectortest` | the vector runner the Go tests share |

Trust boundaries are owned by [SECURITY.md](SECURITY.md).

`zs-conformance` reaches one implementation through a shell adapter
(`crates/zs-conformance/src/adapter.rs`, `adapters/zerosecret.sh`), so its case bodies name
no product. `src/cases/` holds the four protocol families, `src/runner.rs` derives the
negative controls and writes the matrix, `src/fake_upstream.rs` verifies SigV4 signatures
against the vendored vectors in `vectors/aws-sig-v4-test-suite/`, and
`tests/conformance.rs` holds the extraction seam. The crate has no `zs-*` dependency, so
extraction is `git mv`.

Inside `crates/zs-mitm`, `http1.rs` owns the byte layer: the hyper server and client
builders, the fixed replies, the conversion between `hyper::Request` and
`zs_protocol::InjectedRequest`, and the guard that refuses a target with a fragment.
`pipeline.rs` owns one request pipeline for both entry points: `Authorize` (scope and the
identity check), `Inject` (the only caller of `materialize` on the request path; the
`/.zs/presign` route calls it directly) and `Forward` (the upstream send and its one retry).
An upstream connect tries every resolved address through `zs-upstream` (2 s each, 5 s in
total). The upstream and the client TLS handshakes each have 10 s, a client request head 30 s,
and an upstream response head 600 s, the request timeout of common LLM API clients. A late
upstream answers 502 `upstream unreachable`; a late client is disconnected. The forwarded
`Host`, which a signing scheme signs, names the origin host, and the upstream port when the
binding reaches that same host on a non-default port. `proxy.rs` keeps classification, the audit and diag
vocabulary, and the entry-point plumbing (ADR-0039). `ca.rs` owns `LocalCa`:
certificate minting and the public load entry points. Secure CA storage is private to `ca/platform/`. One shared engine decides
every transition; each adapter only reads, writes a new record after an absence check,
deletes the exact macOS legacy item, and classifies native results.

| Module | Owns |
|---|---|
| `platform/mod.rs` | Compile-time dispatch to one adapter per supported OS; the fixed `secure CA storage unsupported` error elsewhere |
| `platform/record.rs` | The versioned, bounded record codec; CA reconstruction; key and certificate validation |
| `platform/state.rs` | The directory lock, `.ca-storage-id`, the fail-closed transition engine, including migration order, and the conditional retire |
| `platform/macos.rs` | The default keychain through `/usr/bin/security`: the lock check, exact items, bounded calls, the legacy item |
| `platform/linux.rs` | The Secret Service default collection over an encrypted D-Bus session (`dbus-secret-service`) |
| `platform/windows.rs` | Credential Manager generic credentials (`windows-sys`) |

`zs-mitm` declares its native dependencies per target: `dbus-secret-service` with
`crypto-rust` for Linux, and `windows-sys` with `Win32_Security_Credentials` for Windows.
macOS adds no native crate. Storage rules, failure behaviour and limits are owned by
[SECURITY.md](SECURITY.md) §6; the persistence choice is [DECISIONS.md](DECISIONS.md)
ADR-0023. `device_store.rs` writes, reads and deletes the device record through the same
adapters, under its own service (§4, ADR-0036).

Inside `apps/zs`, `main.rs` owns argument parsing, subcommand selection, and exit mapping.
`run.rs` owns the agent startup sequence: `prepare` (configuration, subject, audit journal,
CA, grants and control-plane enrolment), `start_services` (proxy and listeners, owned by
one task set that aborts on drop), `build_child` and `wait_for_child`, then audit
shipping. `login.rs` owns `zs login`, `zs logout` and the device line of `zs status`.
`device.rs` owns the native device record codec and `.zs-device.json`. The CA phase is one
isolated `LocalCa::load_or_create_secure` call inside `prepare`. It runs before the async
runtime, control-plane enrolment, any listener, any background task, and the child, so a CA
failure exits 1 with nothing to release. No shipped path calls the plaintext
`LocalCa::load_or_create`.

**A language-neutral spec and golden vectors hold the engine and the control plane in
step.** A vector lives next to the code that owns its contract: `crates/zs-grant/vectors/`,
`crates/zs-policy/vectors/`, `crates/zs-wire/vectors/`, and `control/vectors/` in the
commercial repository for federation, dashboard forms, OIDC ID tokens, and URL and
identifier rules. A vector is a JSON file with `about`, a `version`, and `cases`; each case
pins exact bytes, an exact error text, or an exact status code. Every directory has an
`INDEX.json`, and a meta-test in each language fails when a listed file or case did not run,
or when a file is not listed. Rust reads a vector with `include_str!`; Go reads it by a path
relative to its module, so the Go tests run only inside the commercial repository. A
changed vector is a contract change: the engine workspace and the commercial suite must
both be green before the pin moves. The spec owns the wire schema (ADR-0048 D7); `zs-wire`
is the agent's implementation of it.

**Dependency rule:** `apps/` depends on `crates/`. Crates never depend on apps. A crate
may depend only on crates listed **above** it; every dependency must appear strictly
earlier. The list above is a topological sort of the real graph.

`MAP` in `apps/zs/tests/dependency_rule.rs` is the authority; the list above mirrors it.
Five tests enforce this in CI: the order really is a topological sort, every named crate
exists, every workspace member is covered, members are unique and match, and the
`workspace = true` line under each `[lints]` table is not mistaken for a dependency.
Corrected 2026-09-11 — the previous ordering was violated by its own specification
(`zs-materializer` above `zs-credential`, `zs-protocol` above `zs-credential`).

`zs` and `control` deploy independently because their trust boundaries are unrelated, and
the v2 `gateway` will be a third for the same reason. Only the first two exist in v1.

The dashboard is server-rendered inside `control/` — `templ` templates and one inline
stylesheet, served by a shared shell. No npm, no bundler, no client framework, no second
type declaration of `Resource`, `Policy`, `Grant`, or `AuditRecord`. See
[DECISIONS.md](DECISIONS.md) ADR-0009.

Corrected 2026-09-17: this section previously named **htmx and Tailwind via its standalone
CLI**. Neither was ever used — `grep -rn 'htmx\|tailwind' control/` returns nothing. A
build-step dependency named in the architecture but absent from the code is the drift
ADR-0008 exists to prevent.

## 3. Request lifecycle

HTTP:

```mermaid
flowchart TD
    A["my-service<br/>GET https://api.stripe.com/v1/customers"]
    B["zs-mitm<br/>terminate TLS, present a locally minted certificate"]
    C["zs-protocol<br/>match destination → resource stripe-production"]
    S["zs-mitm<br/>path in the binding's paths? no → forward without a credential (ADR-0027)"]
    D["zs-grant<br/>verify subject, resource, protocol, expiry"]
    E["zs-policy<br/>permits: is the operation in the grant's operations?"]
    F["zs-materializer<br/>retrieve → credential value (exchange: roadmap)"]
    G["zs-proto-http<br/>inject Authorization: Bearer"]
    H["zs-audit<br/>record the decision. never the value"]
    I["api.stripe.com"]

    A --> B --> C --> S --> D --> E --> F --> G --> H --> I
```

PostgreSQL:

```mermaid
flowchart TD
    A["psql or application<br/>connect 127.0.0.1:PORT"]
    B["zs-proto-postgres<br/>parse the startup message → resource"]
    C["zs-grant + zs-policy"]
    D["zs-materializer<br/>static password (a temporary role for the session is roadmap)"]
    E["zs-proto-postgres<br/>complete SCRAM upstream with the materialized credential"]
    F["postgres upstream"]

    A --> B --> C --> D --> E --> F
```

The client's own authentication to the local listener is the ZeroSecret session, not a
database password.

A resource with an `aws_ssm` source (ADR-0041, ADR-0043), first use after a grant is minted:

```mermaid
flowchart TD
    A["zs agent<br/>POST /wire/grant over mTLS"]
    B["control<br/>signed grant + ES256 identity token for that grant"]
    C["zs-materializer StoreRegistry<br/>source kind aws_ssm → GrantBoundCache"]
    D{"value cached for this resource,<br/>grant id and source?"}
    E["SsmStore → AWS STS<br/>AssumeRoleWithWebIdentity, session policy for one parameter"]
    F["SsmStore → AWS SSM<br/>GetParameter, SigV4 signed with the session keys"]
    G["value in memory until the grant expires, at most 300 s"]
    H["inject into the request or the L3 handshake"]

    A --> B --> C --> D
    D -->|no| E --> F --> G --> H
    D -->|yes| H
```

The AWS session is kept per resource and role and refreshed 60 s before it expires. A
revocation or a source change drops the session and the value.

## 4. Signed grants

The agent does not call the control plane on every request. It verifies a signed grant
offline, which is what makes a control-plane outage a bounded degradation rather than a
total one (ADR-0004).

```mermaid
flowchart LR
    A["SSO identity"] --> B["Control plane"]
    B --> C["Policy evaluation"]
    C --> D["Signed grant<br/>minutes TTL"]
    D --> E["Agent verifies offline<br/>zs-grant"]
```

```
subject         alice@company.com
workload        claude-code
resource        stripe-production
host            api.stripe.com
protocol        https
upstream_host   api.stripe.com
upstream_port   443
upstream_tls    default
local_endpoint  false
credential      <reference, never a value>
operations      [GET, POST]
environment     development
expires_at      2026-09-05T14:12:00Z
```

Signed by the control plane. Verified by `zs-grant` in the agent.

**The grant names the upstream connection (ADR-0038).** The control plane signs resolved values
from the resource's `connection` block, so `upstream_host` and `upstream_port` are never empty.
At startup, `zs run` compares each binding with its grant before any listener or child starts.
A binding field that is set must equal the signed value. A field that is left out takes it:

| Binding field | Signed | Note |
|---|---|---|
| `host`, `protocol` | yes (ADR-0037) | must equal the grant |
| `upstream_host`, `upstream_port` | yes | may be left out |
| `upstream_plaintext`, `upstream_ca`, `upstream_cert_sha256` | yes, as one `upstream_tls` mode | may be left out, except `upstream_ca` when the mode is `ca-sha256`: the CA bundle stays a file, and only its SHA-256 is signed (`zs ca-sha256 <file>`) |
| `local_endpoint` | yes | may be left out |
| `listen_addr`, `listen_allow` | yes, in a version-3 grant (ADR-0065) | may be left out. A non-loopback `listen_addr` and its `listen_allow` must equal the grant, or the run stops; a loopback `listen_addr` that the grant does not carry stays local |
| `listen_socket_dir` | no | local. A Unix socket serves only the agent's OS user (SECURITY §3) |
| `auth`, `listen_port`, `paths`, `auth_source`, `client_auth_plugin` | no | local; SECURITY §3 says why |
| `user` | no | local. On `mongo`, the SCRAM user. On `postgres` and `mysql`, the only user a client may name; the agent refuses another before materialization. On `redis`, the user the agent authenticates as; a client may name only it, or `default` when the binding has no `user` (SECURITY §3) |

The connection is fixed for the life of the run. A renewed grant with another connection is
skipped, and a request whose grant differs is denied. For https and http, a CONNECT to a port
that is neither the signed port nor the protocol default is denied. An admin sets the values in
the dashboard. A binding that sets a non-default value stops after the upgrade until the admin
sets it, and the stop line names the field.

A grant carries a credential **reference**, never a credential value. Materialization
happens after verification, inside the data plane.

Revocation lag is about one second for a connected agent (ADR-0064). When the control plane's
`LISTEN` connection is lost, the next held request answers within **5 s**; a connection that
dies without closing is found within 35 s, and until then a change waits for the **25 s** hold.
When the agent's revocation requests fail, it retries from 1 s up to the **refresh interval**
(60 s), and learns of a change at the first answer. An agent that cannot reach the control
plane falls back to the TTL bound, because it cannot learn of a revocation until it next
connects. Both bounds are documented in [SECURITY.md](SECURITY.md) §3, not hidden.

**Implementation status, 2026-09-13 — stated rather than implied.** The control plane
mints and signs grants, evaluates policy before minting, and verifies device signatures
(`control/`, steps 7–11 of the v1 plan). `zs-grant::verify` checks signature, expiry,
subject, workload, resource, and operation against a canonical payload.

**The agent consumes grants (step 14).** `apps/zs` authorizes every request against a
verified, control-minted grant — no local policy file, no fail-open fallback. Its config
file carries resource-to-host bindings and pinned verifying keys only, and confers no
authority (ADR-0017). The offline-verification property described above is a property of
the running agent, not only of the crate.

**Grant revocation exists (step 22, ADR-0018).** `POST /wire/revoke` records a withdrawal
durably; the agent fetches the list on its held revocations request and refuses a revoked
grant before its expiry. Expiry is therefore no longer the only revocation mechanism. An
operator revokes a grant ID from the dashboard (`POST /grants/revoke`). The refresh loop
renews a grant before it expires, never a revoked one, and revoking any grant in a renewal
chain stops the session (ADR-0026).

### The wake path

`GET /wire/revocations` answers a change when it is written, not on the agent's timer. The
agent sends the cursor of its last answer as `after`. The control plane holds the request when
the cursor still matches, releases every database resource, and answers when the organization's
policy version or revocation set changes, or after 25 s. The answer carries the organization's
current `policy_version` and a new `cursor`. An answer without a `cursor` (a control plane
from before this release) makes the agent sleep the refresh interval, so an old control plane
is never polled fast.

```mermaid
sequenceDiagram
    participant D as Dashboard
    participant DB as PostgreSQL
    participant C as Control plane
    participant A as Agent
    A->>C: GET /wire/revocations?after=cursor
    Note over C: held, no DB connection
    D->>DB: INSERT policies (version 8)
    DB-->>C: NOTIFY zs_wire, org
    C-->>A: 200 policy_version 8, new cursor
    A->>C: POST /wire/grant (renew)
    C-->>A: signed grant, policy_version 8
    Note over A: sessions on the old grant checked now
    A->>C: GET /wire/revocations?after=new cursor
```

An `AFTER INSERT` trigger on `policies` and on `revoked_grants` calls
`pg_notify('zs_wire', '<schema>/<organization_id>')`. `NOTIFY` is sent at commit, so a change
that rolls back wakes nobody. The schema prefix keeps two schemas of one database apart; a hub
ignores a payload whose prefix is not its own. Each control instance holds **one** `LISTEN
zs_wire` connection outside the pool and fans each notification out to the held requests of
that organization. After 30 s without a notification the hub pings the connection. If the
connection fails, or the ping gets no answer within 5 s, the hub wakes every held request and
reconnects with backoff (1 s doubling to 30 s); each held request answers at once with the state
it reads, and the next request is held at most 5 s instead of 25 s. The design degrades to a
5 s poll, never to a missed change.

A change wakes every held request of its organization at once, and each reads the state with two
queries that queue on the database pool; a policy edit then makes every agent of the
organization mint each of its grants within about a second. Neither burst is spread out in v1.
A failing state read counts in the store error counter under `op="wire_state"`.

A hold costs one goroutine and one TLS connection, and no database connection. The control
plane exposes the number of waiting holds as `zs_control_wire_revocations_waiting`. The
`/wire/revocations` request-duration histogram (`zs_control_http_request_seconds`, by listener
and route) counts the time a request is held, so a held request appears as an observation of
up to 25 s; the buckets reach 30 s so a hold is not counted as `+Inf`. It is not the store's
service time.

**Each request is authorized for its method (ADR-0026).** A binding lists its operations.
The agent checks the request method against the signed grant on every request.

**The subject in the tuple is the signed-in one.** With a stored enrolment, `zs run` uses the
subject of that enrolment, which the control plane wrote on the device row (ADR-0036). Without
one, it uses the session in `.zs-session`, and `$USER` only when there is no session: the
offline path. `/wire/grant` refuses a request subject that is not the row subject. The SSO half
completes through `POST /login/claim` with a form body, so the verifier never sits in a URL that a
log records. The OIDC callback lands in a browser, and the CLI that started the flow would
otherwise never learn who signed in.

**Tenancy is two nested scopes (2026-09-17).** Organization carries the isolation boundary:
policy, grants, audit and revocation are all organization-scoped, and cross-tenant access is
denied on every `/wire/*` route. Project subdivides an already-isolated tenant — a resource
may name one, and a device enrolled into one reaches only that project's resources.

Both scopes are read from the **device's enrolment row**, never from the request body and
never from the client certificate's `O=` field: the body is the caller's own claim, and a
certificate can outlive a device being moved. Both are fixed by the same single statement
that consumes the enrolment token, so there is no window in which one is known and the
other is not.

A resource carrying **no** project is organization-wide and reachable from anywhere in its
tenant, which is what every policy written before project scoping is. A **device** carrying
no project is not the mirror of that: it reaches only unprojected resources, because absent
scope must not become a wildcard.

### Key rings and rotation

Three keys rotate independently: the grant signing key, the federation key and the device CA.
Each is a ring in `ZS_CONTROL_CA_DIR`, with one state file per kind (`keyring-<kind>.json`) that
names the active entry and the published entries. `control keys add|promote|retire|list` edits the
ring; the running control plane rereads it every 10 seconds, so no restart is needed.

A new key is published for 10 minutes before it may be promoted, and a demoted key signs for its
grace period before it may be retired: 320 seconds for the grant and federation keys (one
300-second lifetime plus two 10-second reloads, because an instance signs with the demoted key
until its next reload), 7 days plus 1 hour for the device CA, so every certificate that CA signed
has expired. Device certificates are
not reissued in place; a device gets a certificate from the new CA at its next `zs login`.

The agent does not need a new control-plane address: the revocations response carries the
published grant keys and CA certificates. A key set or CA change does not wake a held request;
the agent learns of it at the next answer, within 25 s. After a failed request the agent sends
the next one without a cursor, which the control plane answers at once, so a proxy that cuts
held requests delays a key or CA change by about one refresh interval plus the time it takes to
cut a hold. The agent verifies a grant under any
published key and trusts any published CA at the wire handshake. An absent or empty set leaves
its current set unchanged, and a set with one invalid entry is rejected whole. The published CA
set is the whole wire trust: once a CA is retired and drops out of the set, the agent stops
trusting it, even when it is the CA pinned at enrolment. A device enrolled before `v0.4.0` has
no stored CA set, so the pinned CA is its set of one until the first refresh.

A device that is offline for the whole 10-minute publish window of a new device CA misses it: after
the promotion its wire handshake fails. It recovers by saving the control plane's current CA
(`GET /ca`) as its `control-ca.crt` and running `zs login` again.

Every control instance must read the same `ZS_CONTROL_CA_DIR`. Instances with separate copies
publish different key sets, and a device that refreshes from one drops the key the other promoted.

The procedure, on the control host:

```bash
# 1. publish the new key; every agent learns it at its next refresh
control keys add grant            # or: federation, ca
# 2. wait 10 minutes, then make it active
control keys promote grant control-k2
# 3. wait the grace period, then drop the old key and its files
control keys retire grant control-k1
```

`control keys promote federation` also reads `<ZS_FEDERATION_ISSUER>/.well-known/jwks.json` and
refuses until the hosted JWKS holds the new `kid`, so upload the `oidc-export` files first. It
also refuses when `ZS_FEDERATION_ISSUER` is not set in its environment. After `retire federation`,
run `oidc-export` again and upload the result, so the hosted JWKS drops the retired key. A refused
command changes no file. Two `control keys` commands on one kind run one after the other (a lock
file beside the state). `control keys list <kind>` prints ids, states and times only. The grant
and federation graces are 320 seconds; the device CA grace is 7 days and 1 hour.


### Device enrolment and stored identity

`zs login` enrols a device once. Later `zs run` commands load that enrolment from the native
store and `$ZS_HOME/.zs-device.json` (`ZS_HOME` defaults to `$HOME`). The decision is
[DECISIONS.md](DECISIONS.md) ADR-0036. The trust boundaries and limits are in
[SECURITY.md](SECURITY.md) §3 and §6.

```mermaid
sequenceDiagram
    participant D as Developer
    participant Z as zs
    participant K as Native store
    participant C as Control plane
    participant I as IdP
    D->>Z: zs login
    Z->>Z: verifier (32 random bytes), challenge = SHA-256(verifier)
    Z->>C: GET /login with cli_challenge and device name
    C-->>Z: redirect to the IdP sign-in URL
    Z-->>D: print the URL, the login code and the device name
    D->>I: sign in
    I-->>D: redirect to /login/callback
    D->>C: GET /login/callback (IdP code)
    C-->>D: page shows the login code, the device name and a confirm button, sets zs_login_confirm
    D->>C: POST /login/confirm (state, page confirm value, zs_login_confirm cookie)
    loop until the sign-in completes (the pending login expires after 10 minutes)
        Z->>C: POST /login/claim (form: state, verifier)
    end
    C-->>Z: subject + self-enrolment token
    Z->>Z: generate the TLS key and the device signing seed
    Z->>C: POST /wire/enroll (token, CSR, device public key)
    C->>C: device row with subject and expiry
    C-->>Z: device_id, organization, client certificate, grant-verifying key and id, wire_url
    Z->>K: write the new record (create-only)
    Z->>Z: save .zs-device.json, delete the old record, write .zs-session
    D->>Z: zs run -- npm start
    Z->>K: read the record for this control URL
    Z->>C: POST /wire/grant over mTLS to wire_url (signed body)
    C->>C: check the row: subject, expiry, membership
    C-->>Z: signed grant with host and connection, or 401 with a refusal code
```

If the save of `.zs-device.json` fails, `zs login` deletes the new record. One enrolment exists
for each control URL. A second `zs login` against the same control URL replaces it.

The native record:

| Part | Value |
|---|---|
| Service | `zerosecret.device.v1` |
| Account | `zs-device-<device_id>` |
| Value | `ZSDV`, version byte `1`, u32 big-endian length of the TLS key PEM, the TLS key PEM, the 32-byte device signing seed |

`.zs-device.json` holds public data only, mode 0600, written to a temporary file and renamed.
It is `{"enrolments": [...]}` with at most one entry for each control URL. Each entry has:

| Field | Value |
|---|---|
| `control` | Control URL, without a trailing `/` |
| `control_ca_sha256` | Lowercase hex SHA-256 of the control CA PEM, with every `\r` removed and outer whitespace trimmed |
| `subject` | Subject from the SSO sign-in |
| `device_id` | Device id from `/wire/enroll`. It names the native record |
| `organization` | Organization of the device |
| `client_certificate` | Client certificate PEM for `/wire/*` |
| `grant_verifying_key_hex` | Pinned grant-verifying key (ADR-0016) |
| `grant_verifying_key_id` | Its key id |
| `wire_url` | Where `zs run` sends `/wire/*` requests |

## 5. Interception layers

The escalation is chosen **per resource** and declared in resource configuration. It is
never a global mode.

| Layer | Mechanism | Used when |
|---|---|---|
| L1 | Explicit proxy — `HTTPS_PROXY` injected into the child process | Default. Dev containers work immediately |
| L2 | Process-scoped `zs run <cmd>` — child environment plus local CA trust | The SDK ignores proxy variables. Validated 2026-09-06 by the synthetic hostname-routing probe and verifier (spike evidence, not published): an unchanged Node/Stripe fixture completes the mapped path with TLS verified on both legs, and the fail-closed controls held. Caveat carried from the probe: SDKs honor `HTTPS_PROXY` when a user or tool sets one, so the managed workspace must clear or pin proxy variables |
| L3 | Protocol listener — one per resource: loopback TCP, a Unix socket or a signed network address (ADR-0065) | PostgreSQL, MySQL (ADR-0029), MongoDB (ADR-0031), Redis (ADR-0057) and every future non-HTTP protocol |
| L4 | Transparent TUN | Deferred. Only when L1–L3 cannot hold the invariant |

Always use the least invasive mechanism that satisfies the invariant.

The child's environment carries the run's credential (ADR-0052). `HTTPS_PROXY`, and
`HTTP_PROXY` when the run has an http binding, is `http://zs:<run token>@<addr>`, and
`ZS_<RESOURCE>_URL` is `http://<addr>/<run token>`. The proxy checks `Proxy-Authorization` on
every request, and the endpoint strips the first path segment before it matches, signs or audits.
`/.zs/presign` strips the token from the URL it re-signs too, so a URL a client presigned on
`ZS_<RESOURCE>_URL` comes back without it. No line on stdout and no `listener_bound` event
carries the token.

**Read-only L3 resources (ADR-0063).** A resource with `access: read_only` gets a version-2 grant
that signs `access` first. The L3 listener then checks commands, never data. PostgreSQL and
MySQL sessions open in the database's own read-only mode (PostgreSQL startup option
`-c default_transaction_read_only=on`, confirmed by the server's report or, below version 14, by
one `SHOW` at login; MySQL `SET SESSION transaction_read_only = ON`), and a scan of each statement
refuses the known ways to switch it off. MongoDB and Redis admit an allowlist of read commands;
MongoDB `getMore` and `killCursors` pass only for cursors that read-only sessions opened. Every
relay polls the session check that travels with the credential and closes an open session
within 5 s when the access of the grant changes or the grant ends. This is a guardrail, not a
boundary (SECURITY §3).

**L3 listener kinds (ADR-0065).** `ResourceBinding::listen` (`apps/zs/src/lib.rs`) gives each
database binding one kind, and the relay binds it through `zs_protocol::FrontListener`. Loopback
TCP is the default: `127.0.0.1` with `listen_port`, or a loopback `listen_addr`.
`listen_socket_dir` gives a Unix socket in that directory, `.s.PGSQL.5432` for PostgreSQL and
`<resource>.sock` for the other protocols. Before the bind, `apps/zs/src/socket_dir.rs` makes a
missing directory with mode `0700` and refuses a directory that is a symbolic link, has another
owner or is group- or world-writable, and a directory with a parent (on the path as written or
after symbolic links are resolved) that is group- or world-writable without the sticky bit or
has an owner other than root or the agent's user. At the socket name it refuses a symbolic link, a file that
is not a socket and a live socket, and it removes a stale socket only after a connect to it is
refused. The socket gets mode `0600`, and at exit the agent removes it when the name still holds
the socket that it bound. A non-loopback `listen_addr` gives a TCP listener on that address; the
agent binds it only when the run holds a valid grant with the same `listen_addr` and
`listen_allow`. The caller check runs for each connection before a byte is read: the peer socket
lookup on loopback, the peer user ID on a Unix socket (both `peer::caller_check`), and the signed
`listen_allow` on a network listener (`peer::allow_list_check`), which audits a refused source
with `source_addr`. When the source of a network connection is an address of this host (a
loopback address, the listener's own address or an address of an interface, read with
`getifaddrs` for each connection), `peer::allow_list_check` also needs the peer socket lookup of
the loopback listener; a lookup that fails or finds no socket of the agent's user refuses. The line `zs: <protocol> <resource> -> <address or socket path>` and the
diag event `listener_bound` name the listener; `listener_bound` and `caller_refused` carry the
kind in `listen` (`loopback`, `unix`, `network`). The child environment follows the kind:

| Kind | PostgreSQL | MySQL | Each database binding |
|---|---|---|---|
| Loopback or network TCP | `PGHOST=<ip>`, `PGPORT=<port>`; an inherited `PGHOSTADDR` is removed | `MYSQL_HOST=<ip>`, `MYSQL_TCP_PORT=<port>` | `ZS_<RESOURCE>_HOST=<ip>`, `ZS_<RESOURCE>_PORT=<port>` |
| Unix socket | `PGHOST=<directory>`, `PGPORT=5432`; an inherited `PGHOSTADDR` is removed | `MYSQL_UNIX_PORT=<socket path>`; an inherited `MYSQL_HOST` and `MYSQL_TCP_PORT` are removed | `ZS_<RESOURCE>_SOCKET=<socket path>`; an inherited `ZS_<RESOURCE>_HOST` and `ZS_<RESOURCE>_PORT` are removed |

The `PG*` and `MYSQL_*` variables come from the first binding of that protocol.

This is not a system-wide proxy. Browsers, banking sites, and unrelated applications are
untouched. ZeroSecret is not Zscaler and must never be described as though it were.

Known hard ground, planned for rather than promised away: certificate pinning, Java and
custom trust stores, container networking, remote workspaces, HTTP/2, HTTP/3 and QUIC,
gRPC, mTLS upstreams, native clients that ignore proxy settings, VPNs, corporate proxies,
EDR products. WebSockets and SDK request signing were on this list and are solved for the
named schemes: a WebSocket binding writes the credential into one JSON field of client
messages (ADR-0034), and `aws-sigv4` re-signs, `hmac-body-signature` and `api-key-header`
inject, on the agent (ADR-0035, ADR-0046).

**HTTP/1.1 only, enforced rather than assumed (2026-09-11).** `zs-mitm` pins ALPN to
`http/1.1` on both the client-facing and upstream legs. An h2-capable client is
negotiated down rather than silently mis-framed — the failure mode where injection does
not happen and nothing denies. HTTP/2 stays on the hard-ground list above; when it is
taken on, the pin is what has to change. hyper reads and writes the framing on both legs
(ADR-0039). The proxy still decides what crosses: a request whose `Transfer-Encoding` is
not exactly one `chunked` is refused, a body over 32 MiB is refused, and a head over
64 KiB is refused (`crates/zs-mitm/src/http1.rs`).

## 6. Materialization modes

| Mode | Meaning | Strength |
|---|---|---|
| Retrieve | Pull a stored credential from a vault | Works everywhere. Weakest |
| Exchange | Identity to ephemeral credential: AWS STS, OAuth token exchange. Not for a database: a database keeps a stored password (ADR-0060). Not implemented: the agent wires `UnconfiguredExchange` (`apps/zs/src/run.rs`), which refuses | Preferred wherever the provider supports it |

Mode is a property of the resource and is visible to the user. The long-term product
story is moving resources from Retrieve to Exchange, where the destination supports it and a
decision does not exclude it (ADR-0060 excludes the database protocols):

```mermaid
flowchart TD
    A["long-lived static secret"]
    B["dynamic credential"]
    C["short-lived credential"]
    D["per-session credential"]
    E["identity-native authentication"]

    A -->|weakest| B --> C --> D --> E

    G(["the goal"]) -.- E
```

The data model carries `materialization.mode` and `materialization.location`
(`agent` | `gateway`) from day one. Applications never see either.

## 7. Authorization is a tuple

Not a credential lookup.

```
human identity + workload identity + destination + protocol operation + environment + session
```

```
alice + claude-code + api.stripe.com + GET    + development → ALLOW
alice + claude-code + api.stripe.com + DELETE + production  → DENY
```

When a binding lists `paths`, the destination includes the request path. A path outside
the list gets no credential and needs no grant (ADR-0027).

This converts credential possession into runtime authorization. It is the differentiator.

**v1 limit, stated honestly:** workload identity is a declared label
(`zs run --as claude-code`) plus process lineage. It is not cryptographic and does not
resist a hostile local process. The agent's listener binds to loopback, which every local
account can reach, so any local account that can reach the port gets the developer's
access, not only processes of the same user. Caller authentication is planned. See
[SECURITY.md](SECURITY.md).

## 8. Configuration source of truth

The control plane owns configuration. There is no committed `zerosecret.yaml`. The committed
`run` block in `zs-policy.json` holds control-plane connection settings only; the control plane
still owns resource configuration (ADR-0036), including each resource's upstream connection
(ADR-0038).

The agent keeps a read-only cache of the last-known resource configuration and grants so
a network blip does not stop work. The cache expires with the grant TTL. Past that, the
agent fails closed.

Rejected: a second self-managed configuration path. It doubles the surface, doubles the
test matrix, and creates drift between what the dashboard shows and what the agent
enforces.

## 9. Engineering constraints

- Units: milliseconds, bytes. UTC everywhere. No local time in any stored value.
- Determinism: seeded RNG only in tests. No wall-clock reads outside an injected clock.
- Failure isolation: a broken protocol implementation denies its own resource. It never
  takes down the agent.
- Fail closed: unknown resource, unverifiable grant, expired cache, or unavailable audit
  sink all mean deny.
- Redaction: a credential value never reaches a log line, an audit record, an error
  message, or a panic payload. Credential types do not implement `Debug` or `Display`.

### Persistence and migration

PostgreSQL startup runs the numbered files in `control/migrations/` (`NNNN_name.sql`, embedded
through `go generate ./internal/store`) with `store.ApplyMigrations`. One transaction takes
`pg_advisory_xact_lock(7239001)`, creates `schema_migrations` if absent, runs each file whose
version is not recorded, in ascending order, as a single argument-less `Exec`, and records the
version. Concurrent control-plane instances queue on the lock, so each file runs once and the
instances do not rely on `IF NOT EXISTS` being atomic. A file that fails rolls the whole run
back: no partial schema and no recorded version. A migration that has shipped is never edited
except to keep it re-runnable; a schema change is a new numbered file. An installation that
ran `0001` before the runner existed runs it once more, so `0001` must stay idempotent.
`store.createSchema` is the one place that still tolerates concurrent creators, only for
`23505`, `42P07` and `42710`. Do not broaden that set.

Schema changes use `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`. Required columns are
backfilled with a default and then have that default removed. A nullable value such as
`project_id` remains nullable; migration must not invent a scope.

The enrolment-token column stores a SHA-256 digest. A legacy plaintext value is no longer
usable against the digest and must fail closed. Upgrade coverage includes
`store.TestMigratingAPreProjectSchemaAddsTheProjectColumn`; a fresh-schema
test alone is not evidence that an existing installation upgrades correctly.

Database test schemas use a per-run timestamp plus counter so concurrent runs do not reuse
state. The persistence migration tests intentionally use fixed schema names and isolate
their rows with per-run identifiers.

## 10. Budget

| Path | Budget |
|---|---|
| HTTP request added latency, warm grant | < 6 ms p95 |
| Agent resident memory, idle | ≤ 60 MB |
| Agent cold start to first proxied request | ≤ 400 ms |

Measured by a benchmark in CI, not by assertion. A change that regresses a budget fails
the build.

**These are budgets for an idle measuring host**, and the added-latency one is the reason
that needs saying. Added latency is the proxied p95 minus the direct-request median on
the same machine. The budget has about 3 ms headroom over the proxy's ~3 ms median;
scheduler preemption on a busy developer host can still consume that headroom without
a change to the proxy.

**Before treating a local `budget_latency` failure as a regression, check `proxied p50`.**
If the median is ~3 ms the proxy is behaving and the host is the variable; a real regression
moves the median, and a 4 ms sleep injected on the proxy path fails the test at ~12 ms.

**`budget_footprint` has the same sensitivity**, observed 2026-09-18: it failed immediately
after three back-to-back `cargo test --workspace` runs had driven the load average to 12.6,
and passed on the same binary once the machine settled to 3.5. **Do not run the budget gates
straight after a full workspace run** — they measure wall-clock, and the suite that just
finished is still the load.
