# ZeroSecret Roadmap

**Status:** Approved direction
**Date:** 2026-09-05
**Owner of:** phases, sequencing, exit criteria

Every phase ends in something demoable to a customer. No phase exists only to enable a
later phase.

## v0 — walking skeleton

Prove the invariant on the narrowest possible path. One protocol, one credential
provider, no control plane, no dashboard.

- `zs run <cmd>` with L1 explicit proxy
- `zs-mitm`: local CA, certificate minting, HTTP/1.1
- `zs-proto-http`: bearer injection only
- `zs-credential`: one provider
- Policy and resources from a local file. Throwaway. Replaced in v1
- `zs-audit`: append-only local journal

**Exit:** an application makes a real authenticated call to a real third-party API with
no credential anywhere in its environment, files, or memory. Verified by inspection, not
assertion.

Status 2026-09-17: the v0 workspace was implemented and tested at 2026-09-06
(the v0 plan, not published, steps 1–9), and everything it described has since been
superseded by v1 — the local policy file confers no authority, and authorization runs off
signed grants (ADR-0017). The interception-redesign probe validated the L2-managed-workspace
path for unchanged Node/Stripe SDKs.

**The real-credential run happened on 2026-09-17** and closed the part that had been open
since 2026-09-06. `zs run` against `auth-staging.acme.example` — somebody else's service,
reached over real TLS — returned **200** with the agent-injected credential and **401** with
a wrong one, `zs-verify` reported `leaked: false` over a scan that reached the upstream, and
all ten SECURITY §7 fail-closed rows pass. Evidence:
the v1 demo transcript (not published).

**The exit criterion is met (2026-09-18).** The last clause — *every budget met* — closed
after a real defect was found in the benchmark rather than in the proxy: the p95 index was
off by one, selecting the first element of the slow tail instead of the 95th value, so the
assertion was decided by a single sample sitting on the 5 ms boundary. Fixed, unit-tested,
and mutation-verified (a 4 ms sleep on the proxy path fails it at ~12 ms).

Measured: cold start **150 ms** / 400 ms, RSS **3584 KiB** / 60 MB, added p95 **within 5 ms**
on an idle host. §10 now records that the added-latency budget assumes an idle measuring
host, with the evidence — 31 of 37 runs pass at load average under 4, 8 of 20 at load 9 —
and how to tell a loaded machine from a regression.

**Strict mode was outside v0's criterion and is claimed from 2026-09-18.** The demo resource
is `retrieve`, which the old label read as `not-strict`; ADR-0022 decides strictness by
interception instead, and the resource reports `strict`. v0's criterion never required it
either way.

## v1 — the product

The demo in [PRODUCT.md §4](PRODUCT.md#4-the-demo), end to end.

**Data plane**
- HTTPS: bearer, basic, api-key header, query parameter, custom signing (not implemented as a
  general scheme; two named signing schemes ship, ADR-0035 and ADR-0046)
- PostgreSQL: wire protocol, SCRAM, static password. Temporary role: not implemented
- Interception L1, L2, L3
- Materialization: retrieve. Exchange: not implemented (the agent refuses it)

**Control plane**
- OIDC relying party. Federates to the customer IdP. ZeroSecret runs no user directory
- Organizations, projects, resources, policy
- Signed grant minting, revocation
- Central audit ingest and export
- mTLS device enrolment

**CLI**
- `zs login` `logout` `status` `doctor` `run` `resources`

**Dashboard** — server-rendered from `control/`
- Resource, policy, and member CRUD. Forms, not raw YAML
- Audit browser
- The visual request composer with a live preview of the mutated request is v2. A form
  is enough to prove v1

**The Go port is closed (2026-10-31).** The control plane is the Go module in `control/`.
The Rust reference is deleted (ADR-0047, ADR-0048, ADR-0049). The shared suite, the
vectors, and every commercial SECURITY §7 row run against `control/bin/control`.

**Exit:** five design-partner teams install it, pilot with ten developers each, and say
they would pay. If they instead say an existing product covers enough of this, stop and
re-plan. That answer is worth more than six months of building.

### v1 status, 2026-09-18 — 35 of 35 plan steps

Measured, not asserted. Commands and their output:

```
cargo test --workspace                       357 passed, 0 failed  (with DATABASE_URL; 0 failures without)
cargo fmt --all -- --check                   exit 0
cargo clippy --all-targets -- -D warnings    exit 0
cargo deny check                             advisories ok, bans ok, licenses ok, sources ok
cargo test --release -p zs --test budget_footprint
  cold start 150 ms | RSS 3616 KiB           exit 0   (budget 400 ms)
cargo test --release -p zs --test budget_latency
  added p95 within budget                    exit 0   (budget 5 ms, idle host)
```

**Proxy on hyper, 2026-10-27 (ADR-0039).** Re-measured on the same fixture. The proxy now runs
on hyper, so the numbers moved:

```
cargo test --release -p zs --test budget_footprint
  cold start within budget | RSS 5472 KiB    exit 0   (budget 400 ms; was 3616 KiB)
cargo test --release -p zs --test budget_latency
  proxied p50 3.453 ms, p95 4.717 ms,
  direct p50 0.143 ms, added p95 4.574 ms    exit 0   (budget 5 ms)
```

RSS grew by about 1.9 MiB: hyper keeps a 64 KiB read buffer and a 64 KiB write buffer per
connection, where the hand-written path kept one small `Vec`. Added p95 stays inside the 5 ms
budget. Check `proxied p50` before treating a later failure as a real regression
(ARCHITECTURE §10).

**ARCHITECTURE §10's budgets are met.** Cold start and RSS pass with room to spare — cold start had been reading
442–655 ms, and the cause was macOS verifying a newly linked binary on its first execution,
which `budget_footprint` measured in full because `cargo test` relinks `zs` before every
run. The test now warms the binary before timing — one sample still, no retry, and a 400 ms
mutation still fails it.

**`budget_latency` had an off-by-one in its p95 index** — `samples[len * 95/100]` selects
index 95 of 100, the first element of the slow tail, rather than the 95th value at index 94.
With ~5 samples above 5 ms in every run, one element on the boundary decided the verdict.
Fixed with a nearest-rank `percentile()` helper, four unit tests on the boundary case, and
the sample count raised to 500. **Mutation-verified:** a 4 ms sleep on the proxy's inject
path fails it at ~12 ms.

The budget is a delta with ~2 ms of headroom over the proxy's ~3 ms median, so it still
needs an idle measuring host: 31 of 37 runs pass at load average under 4, 8 of 20 at load 9.
§10 records that, and how to distinguish a loaded machine from a regression.

Every scope line above is implemented **except** three: the PostgreSQL temporary role, the
exchange materialization mode, and custom signing as a general scheme. ADR-0014 deferred
custom signing to v2, and ADR-0035 and ADR-0046 later shipped two named schemes
(`aws-sigv4`, `hmac-body-signature`). "Organizations, **projects**, resources, policy" is now fully
met: project scoping landed 2026-09-17 as step 21b, with ten tests that all run inside a
single organization so only the project can produce the denial.

**All 35 plan steps are done.** Steps 30 and 33, open since v0, closed together on
2026-09-17: the demo ran against `auth-staging.acme.example` — a third party that validates the
credential — and the owner documents were then written *from* the run rather than ahead of
it. Evidence: the v1 demo transcript (not published).

**The v0 exit criterion is met.** All five of PRODUCT §4's lines run against a counterparty
that **validates**, each with a negative test proving the counterparty really does refuse:

| §4 line | Proven against |
|---|---|
| `env \| grep` → nothing | the credential value, absent from the child that made the call |
| `zs login` (SSO) | a real OIDC flow, RS256 verified against a fetched JWKS |
| `zs run` → the API call works | **`auth-staging.acme.example` — a real third party: 200 with the injected token, 401 with a wrong one** |
| child environ → no key | both the HTTPS and psql paths |
| `psql` → no password | a real PostgreSQL that refuses a wrong password |

**"A real third-party API" is now closed.** It was the last qualification: until 2026-09-17
every validating counterparty ran on this machine, and the one real third party in play
answered 404 to everything, proving delivery and not acceptance. `auth-staging` is somebody
else's service, reached over real TLS, and it refuses a wrong credential.

**v1's last qualification — "strict mode not met on the HTTPS path" — is resolved
(2026-09-18), by reporting the property correctly rather than by building a mechanism.**

The old qualification read the strict label off the materialization mode, so a `retrieve`
resource printed `not-strict`. PRODUCT §7 defines strict mode as *the workload gets access
without receiving the upstream credential*, which asks who holds the credential — and on
both intercepted paths the agent presents it and the workload holds nothing. ADR-0022 moves
the label onto interception. The demo resource against `auth-staging.acme.example` is `strict`,
and the evidence is the `zs-verify` run already in the repository: the credential was absent
from the child that made the authenticated call.

The claim is bounded to intercepted paths, a bound SECURITY §3 already documents. Nothing is
claimed for unintercepted traffic.

## v2 — reach and delegation

Only after v1's exit criteria are met.

- Gateway: private resource connectivity, resource-side materialization
- Database protocols for a customer's wider adoption, each with its own spec, plan and review: MySQL (ADR-0029), then MongoDB (ADR-0031)
- Cryptographic workload identity, replacing the declared label
- Approvals for production operations
- Device posture
- SIEM export, SCIM
- Compliance Automation: Automated evidence generation mapped to SOC 2 (isolation and access controls), NIST AI RMF (AI risk management and secret exposure), and EU AI Act (data governance and logging requirements)
- Visual request composer. Reference feel: Postman, Bruno, Insomnia. One JS island
  inside the server-rendered dashboard, not a second application

## Deliberately unscheduled

Not "later". Not on the roadmap. Adding one of these requires a written decision that
says which of the constraints below no longer holds.

SMTP, package registries, gRPC, Kafka, plugin system, TUF
signing, WASM plugins, column masking, HTTP/3 and QUIC, private control-plane
deployment, a vault of our own, the webhook product.

## Why this shape

The previous repository reached 198k lines of Go, 153k lines of docs,
and 491 commits across two products, five protocols, and a signed plugin system — before
one customer validated the core claim. Every phase above is a customer conversation, not
a technical milestone.
