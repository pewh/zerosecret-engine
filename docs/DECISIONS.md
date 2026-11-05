# Decision Log

One entry per irreversible choice. Newest first. A decision is changed by adding a new
entry that supersedes the old one, never by editing history.

Format: context, decision, consequence, what would reverse it.

---

## ADR-0051 — The commercial suite is Go; tests that need engine internals live here

**2026-11-04 · Accepted** · owner request 2026-11-03 ("port suite to go") · amends ADR-0050
D1, D2, D3, D6 and D8

The commercial suite was a Rust crate in the commercial repository, `apps/zs-control-tests`: 25 test
binaries and 269 test functions. Its harness spawned the `zs` binary and the Go control binary,
and opened TLS, minted grants and read the schema in Rust. The owner asked for a Go suite and
for no Rust in the commercial repository. That left 39 tests that inspect engine internals
without a home: they cannot move to Go, because they call the engine in process.

**Decision.**
- **D1.** Those 39 tests live here, in `apps/zs/tests/`: `signed_connection_in_process.rs`
  (12), `wire_client_contract.rs` (3), `startup_lifecycle_agent.rs` (17) and
  `agent_flags.rs` (7). A test that needs engine internals is added here, not in the
  commercial repository. They run in `check` under `cargo test --workspace --locked`.
- **D2.** The commercial suite is the nested Go module `control/e2e` in the commercial repository, one
  package per former Rust file, with `control/e2e/internal/harness`. It links no engine
  crate: it runs the `zs` binary built from a pinned checkout of this repository (`ZS_BIN`)
  and the Go control binary (`ZS_CONTROL_BIN`).
- **D3.** The commercial repository holds no Cargo workspace, `Cargo.lock`,
  `rust-toolchain.toml` or `deny.toml`. This repository is the only Rust workspace;
  `engine-pin` remains the join between the two.
- **D4.** Coverage parity is recorded, not asserted by a script: the baseline was 269 tests;
  39 moved here and 230 are Go tests there. The commercial harness's grant verifier is pinned
  to this repository's golden vectors (`crates/zs-grant/vectors/grant-file.json`), run as a Go
  test, so the two implementations cannot drift silently. A vector change is a contract
  change: both sides are green before the pin moves.

**Consequence.** A test that needs engine internals has a home here, and the commercial
repository has one language. The moved tests run in this repository's CI before a tag exists,
so a pin bump cannot carry a regression they would catch. A commercial test reaches the agent
only through its binary and the wire contract.

**Reverse it if** the commercial suite needs in-process access to engine internals that the
process interface cannot expose. The answer is a test hook in the engine or a test here, not
a second language in the commercial repository.

---

## ADR-0050 — This repository is the upstream; the commercial layer pins a release of it

**2026-11-02 · Accepted** · owner request 2026-11-02 (Option B) · supersedes ADR-0045 D3

ADR-0045 D3 kept engine work in a private repository and exported a fixed file list for each
release. The export ran once: this repository held commit `86a1be8`, tag `v0.1.0`, with a green
CI. From then on every engine file existed twice, the export script had to be maintained, and a
change from an outside contributor was ported by hand. The owner chose to make this repository
the upstream.

**Decision.**
- **D1.** This repository is the upstream for all engine code: `crates/*`, `apps/zs`,
  `tools/zs-verify`, the conformance suite and its fixtures, and the engine-internal tests
  moved here by ADR-0051. Engine changes are made here, under the DCO rule of ADR-0045 D5,
  and a pull request is merged here.
- **D2.** The commercial layer — the control plane, its tests, the customer harness records and
  the execution state — lives in a separate private repository that clones this one beside
  itself as `engine/`: locally a symlink, in CI a checkout at the pinned tag. No commercial
  source file is tracked here.
- **D3.** This repository keeps its own Cargo workspace and its own `Cargo.lock`. The
  commercial repository holds no Cargo workspace (ADR-0051 D3): it builds the `zs` binary
  from the engine checkout and runs it as a process, so no change here needs a lock file
  there until a tag moves.
- **D4.** The commercial repository pins a `vX.Y.Z` tag of this repository and the commit that
  tag resolves to, and refuses to build when the tag resolves to another commit. A published tag
  is therefore an identity, not a moving label; moving one breaks every pin that names it.
- **D5.** This repository is public since 2026-11-03. The commercial CI checks out the pinned tag
  with a read-only deploy key, or with its default token now that the tag is publicly readable.
- **D6.** Engine tests run only in this repository's CI: `gates`, `check`, `conformance`,
  `db-real`, and the macOS, Linux and Windows native jobs. The 39 tests moved here by
  ADR-0051 run in `check`. `macos-check` and `macos-native` run only while this repository is
  public, where hosted macOS minutes are free.
- **D7.** The export tooling of ADR-0045 D3 is deleted and not maintained here:
  `release/build-tree.sh`, `release/public-set.txt`, `release/overlay/` and
  `release/README.head.md`. The release gates are `tools/public-gates.sh`, run by CI on every
  push and pull request. The forbidden-name list stays in the commercial repository as the
  source of this repository's `FORBIDDEN_NAMES` secret, because the gate must not contain it.
- **D8.** Only this Cargo workspace builds (ADR-0051 D3). In CI it builds into `engine/target`;
  locally the clone may carry an untracked `.cargo/config.toml` pointing at a shared `target/`,
  so an engine build does not fill a second one.

**Consequence.** One copy of each engine file. An engine change and the commercial change that
uses it are two commits in two repositories, joined by a pin bump, so a commercial test that
needs new engine behaviour waits for that behaviour to land here. The owner documents — PRODUCT,
ARCHITECTURE, SECURITY, ROADMAP and DECISIONS — exist in both repositories and can drift; an
engine-facing change to one is made here. The commercial suite reaches this repository only
through the pinned binary and the wire contract (ADR-0051). This entry and the commercial
repository's copy record the same decision from opposite sides.

**Reverse it if** most changes need an engine edit and a commercial edit in the same step, so
that pin bumps become the bottleneck. Then the engine returns to the commercial repository with
an export, as ADR-0045 D3 had it.

---

## ADR-0049 — The Rust control plane is deleted before C7 is proven

**2026-10-31 · Accepted** · owner override 2026-10-31 of plan D3 Step 1 · amends ADR-0047 D5 and ADR-0048 D4 and D5

ADR-0048 D4 and D5 held the delete behind two conditions: every gate green, and the real AWS
SSM E2E (credential-sources C7) green against the Go control plane. On 2026-10-31 the owner
overrode the plan's Step 1 precondition. The two integration applications pass their full E2E
runs against `control/bin/control`; both exit 0. C7 is not applied yet: the DevOps change is
pending and C7 will run against the Go binary only. Keeping `apps/control` until then means
every control-plane change is written twice while C7 waits.

**Decision.**
- **D1.** The Go control plane in `control/` is the only control plane. The dual-language rule
  ends.
- **D2.** `apps/control` and `.sqlx/` are deleted before C7 is proven.
- **D3.** Recovery is git history. The last commit that contains `apps/control` is the
  reference; no copy stays in the tree.
- **D4.** C7 runs against `control/bin/control`. The vectors, the shared suite and the process
  interface judge it; no Rust comparison run is required.

**Consequence.** The tree has one control plane and one implementation.
The risk ADR-0048 D5 carried moves to C7: a defect that only the real SSM path shows is found
after the reference is gone. The vectors and the shared suite still pin what the Go binary
must do. A C7 failure those gates cannot localize is recovered from git history, not from a
live second implementation. ARCHITECTURE, SECURITY and ROADMAP now describe one control plane.

**Reverse it if** C7 fails in a way the vectors and the shared suite cannot localize. Restore
`apps/control` from the last commit that contains it, run both binaries against C7, and keep
the dual-language rule until the Go defect is fixed and a vector pins it.

---

## ADR-0048 — The Go control plane: location, judge, stack and cutover

**2026-10-31 · Accepted** · spec docs/specs/2026-10-31-control-plane-go.md · amends ADR-0047 D5, ADR-0009 and ADR-0011

ADR-0047 ruled that the team layer moves to Go and that the move starts with a spec and golden
vectors. The owner accepted that spec on 2026-10-31. The spec says what the port builds. This
entry records the choices a later plan cannot quietly change: where the module lives, what
decides the port is done, which stack it uses, and when the Rust control plane is deleted.

**Decision.** D1 to D5 are the owner's rulings O1-O5 in the spec. D6 and D7 are the spec
author's calls, recorded here so a plan cannot change them unnoticed.

- **D1.** The Go control plane is a top-level `control/` module in this repository.
- **D2.** One process-level suite judges the port. A control plane passes when the commercial
  SECURITY §7 rows, `apps/zs-control-tests` driving the binary named by `ZS_CONTROL_BIN`, and
  the security set moved from `apps/control/tests` all pass against it. Tests that assert only
  in-memory detail are rewritten in Go.
- **D3.** The stack is `chi` for routing, `templ` for templates, `sqlc` over `pgx` v5 for
  storage, `cedar-go` for policy, `go-json-experiment/json` for the wire, and the Go standard
  library for crypto.
- **D4.** `apps/control` is deleted only after those gates pass and one end-to-end run of each of
  the two applications that prove integration passes against the Go control plane. This adds a
  condition to ADR-0047 D5.
- **D5.** The port starts on acceptance of the spec and does not wait for credential-sources C7.
  The delete (D4) also waits for C7's real AWS SSM E2E against the Go control plane. Until both,
  a behaviour change in the control plane is written in both languages or it waits.
- **D6.** The control plane takes the PostgreSQL schema it creates and uses from
  `ZS_CONTROL_DB_SCHEMA`, default `public`, and refuses a value that does not match
  `[a-z_][a-z0-9_]{0,62}` before it opens a connection. The shared suite runs each process in a
  fresh schema, and a deployment can keep the control plane out of `public`.
- **D7.** The spec owns the wire schema. ADR-0011's argument that compiling the shared Rust types
  into both sides gives one schema does not survive a control plane that cannot compile them.
  JSON over HTTPS stands. `zs-wire` becomes the agent's implementation of the spec's schema, and
  the golden vectors pin both implementations.

**Consequence.** The control plane exists twice until the cutover, and the vectors are the
contract that keeps the two honest. `control/` joins CI from its first commit, and
`tools/public-gates.sh` refuses to publish a tree that contains it. ADR-0009's rule against a
separate frontend application stays. Its templates become `templ` and its location becomes
`control/`.

**Reverse it if** a decision on the credential release path cannot be pinned by a vector. That
decision then stays in Rust, as ADR-0047 says.

---

## ADR-0047 — The team layer is Go; the engine stays Rust

**2026-10-30 · Accepted** · owner ruling 2026-10-26 (journal `sandbox-runtime-parent-spike`), queue position 2026-10-30 · supersedes ADR-0001 for the control plane and the language of ADR-0009

ADR-0001 put the control plane in Rust for one reason: `zs-policy` and `zs-grant` compile into
both the control plane and the agent, so the two cannot drift. PRODUCT.md §8 makes the engine
open and the team layer commercial, and ADR-0045 publishes the engine without `apps/control`.
The team layer is mostly integration work (SSO, CRUD, audit export, background jobs), which is
the cost ADR-0001 accepted. On 2026-10-26 the owner ruled that the team layer is Go.

**Decision.**
- **D1.** The engine stays Rust: agent, CLI, MITM engine, protocols, materializer, policy
  evaluator, audit primitives and the conformance suite. The control plane (`apps/control`) and
  its dashboard are ported to Go.
- **D2.** Shared compilation no longer prevents drift. A language-neutral spec and golden vectors
  do. Both implementations run the vectors in CI. At minimum, the vectors cover the canonical
  grant payload and signature (the frozen File-grant vector in `zs-grant`), the federation token
  bytes (credential-sources C1), the `zs-wire` JSON, and policy decisions.
- **D3.** Policy decisions come from one policy set. Go loads the same `zerosecret.cedar` and
  `zerosecret.cedarschema` with `cedar-go`. Go evaluation is accepted only when it matches
  `cedar-policy` on the differential grid of ADR-0040, including the reason text and the chosen
  grant.
- **D4.** The port starts after credential-sources Phase C. Phase C builds C1 and C5 in Rust
  (owner ruling 2026-10-28). The first step is the spec and the vectors. No
  Go code is written before the owner accepts the spec.
- **D5.** The Rust control plane stays the reference until the Go control plane passes the
  vectors and every control-plane SECURITY §7 row. After that, `apps/control` is deleted.
- **D6.** The dashboard stays server-rendered, with no npm and no separate frontend
  application. Only the template language changes.

**Consequence.** ADR-0001 now applies to the engine only. ADR-0009 keeps its rule against a
separate frontend application, but its templates move from `maud` to Go. The JSON wire of
ADR-0011 stays. Its argument that the shared Rust types are the one schema does not hold any
more, so the spec owns the wire schema. The tests in `apps/zs-control-tests` link the Rust
control crate, so they must drive the control plane as a process before the port can pass them.

**Reverse it if** `cedar-go` cannot match `cedar-policy` on the differential grid, or a decision
on the credential release path cannot be pinned by a vector. In that case, that decision stays in
Rust.

---

## ADR-0041 — A remote credential source is reached through STS web identity

**2026-10-30 · Accepted** · design `docs/specs/2026-10-24-credential-sources-design.md` §2.5-2.7 and SSM spec `docs/specs/2026-10-23-aws-ssm-web-identity.md`, accepted by the owner 2026-10-24 · extends ADR-0043

The first remote store is AWS Systems Manager Parameter Store. The agent must read a SecureString
with no AWS access key on the laptop, and the control plane must say which workload may read which
parameter.

**Decision.** The control plane signs a short-lived ES256 identity token, AWS STS exchanges it for
a role session, and the agent reads the parameter with that session.
- **D1.** The token key is P-256 PKCS#8 at `<ZS_CONTROL_CA_DIR>/oidc-signing.key`, mode 0600,
  created once and reused. The `kid` is the RFC 7638 thumbprint. The published JWKS holds the
  public coordinates only.
- **D2.** The issuer comes from `ZS_FEDERATION_ISSUER` and must be an `https://` URL with no
  trailing slash. The claims are `iss`, `aud` (`sts.amazonaws.com`), `sub`, `zs_subject`, `jti`
  (the grant id), `iat` and `exp` (the grant expiry). `sub` is
  `zs:<org>:<project or ->:<resource>`; a segment that is empty, contains `:` or contains a
  control character is refused, and `sub` stops at 255 characters.
- **D3.** The control plane mints the token only for a source that names an identity audience
  (`aws_ssm`). A `file` grant carries none. An `aws_ssm` grant minted with no issuer configured
  is refused with 403 and `control: grant refused for <resource>: no federation issuer
  configured`.
- **D4.** The JWT header, payload, `kid`, JWKS and one signed token are frozen in
  `apps/control/src/federation.rs`. A later Go control plane (ADR-0047) runs the same vector. The
  JSON byte order is fixed by construction, so a dependency feature cannot change it.
- **D5.** `control oidc-export <dir>` writes `.well-known/openid-configuration` and
  `.well-known/jwks.json`, the two documents the AWS OIDC provider needs.
- **D6.** `ZS_CONTROL_ORG` and the `/enrollment-token` organization field refuse `:` before
  anything else, because that character separates the `sub` segments.

**SECURITY §4 rule 1 exception.** A value read from `aws_ssm` stays in memory for the life of its
grant, capped at 300 seconds after the fetch (design D7), so a second connection on the same
workload does not call STS again. Rule 4 keeps its full force: no value reaches disk. A `file`
credential keeps rule 1 unchanged.

**Consequence.** The control plane holds a second private key. Its loss stops new tokens until a
new key is made and its JWKS is published. The agent trusts the issuer document, so the JWKS must
answer at the issuer the token names, or STS refuses every token.

**Alternatives.** Static AWS keys on the laptop put a long-lived secret back on disk, which is the
product's non-goal. Instance roles do not exist for a developer laptop. An agent that asks STS
with its own credential moves the trust decision to the agent, and the control plane would no
longer decide which workload may assume which role.

**Reverse it if** the deployment cannot publish an OIDC issuer and JWKS, or a later store cannot
use web identity. Then that store needs its own trust path, and this ADR covers `aws_ssm` only.

---

## ADR-0046 — The payment-gateway signing scheme becomes `hmac-body-signature`

**2026-10-29 · Accepted** · spec `docs/specs/2026-10-29-hmac-body-signature.md`, accepted by the owner 2026-10-29 · supersedes the vendor-named scheme of ADR-0035

ADR-0035 added an `auth` scheme for one payment gateway and named it after the vendor. The
public engine carries no vendor names (ADR-0045), and the signing rule is generic HMAC.

**Decision.**
- **D1.** The scheme is `hmac-body-signature`. The binding names `id_header`, the request header
  whose value is signed, and `signature_header`, the header the agent writes. Both are required.
- **D2.** The signed bytes are unchanged: `METHOD:<id value>:sha256hex(body):<secret>`, keyed with
  the secret, with `{}` for an empty body. A request without the id header is denied before the
  upstream with the fixed text `hmac-body-signature needs its id header`.
- **D3.** The policy load refuses header names that are not HTTP tokens, two names that are equal
  without regard to case, and a `signature_header` of `host`, `authorization`, `content-length`
  or `transfer-encoding`.
- **D4.** The old scheme name has no alias. A policy file that uses it is refused at load.

**Consequence.** Each binding that used the old name changes one line. The SECURITY §7 row keeps
its number, and the matrix keeps 77 rows. The diagnostic log's scheme code is
`hmac_body_signature`.

**Reverse it if** a second HMAC API needs a different signed string; then the string becomes a
setting under a new spec.

---

## ADR-0045 — The engine is published under Apache-2.0 from a private upstream

**2026-10-29 · Accepted** · owner rulings of 2026-10-28 on the open-source release spec, which is not published · applies PRODUCT.md §8

PRODUCT.md §8 makes the engine open and the team layer commercial. A security engineer will not
install a binary that terminates TLS and holds credentials unless they can read its code. This
repository also holds the control plane, customer records and execution state, and its history
names customers, hosts and network endpoints. The engine needs a public home without them.

**Decision.**
- **D1.** The engine and its conformance suite are licensed under Apache-2.0. The licence has a
  patent grant and is the licence of the vendored SigV4 test vectors.
- **D2.** The public repository is new, with a fresh history. `apps/control` and its tests stay
  private. This repository's history is never published.
- **D3.** Engine work stays in this repository. For each release, a script copies a fixed list of
  files into an empty directory and runs the release gates on the copy. The owner then pushes the
  copy as one commit. A maintainer ports changes from outside contributors back by hand.
- **D4.** A fork that changes the code must use a different name. Unmodified redistribution may
  use the name. `TRADEMARK.md` in the public repository states this.
- **D5.** Contributors sign off each commit under the Developer Certificate of Origin. There is no
  contributor licence agreement.
- **D6.** Releases are source releases. There is no crates.io publication and no binary until the
  API is stable and the owner approves.
- **D7.** Security reports go through GitHub private vulnerability reporting on the public
  repository until a reporting address exists.
- **D8.** Public CI runs on GitHub-hosted `ubuntu-24.04` runners. If account billing blocks them,
  the public README states the gap. The macOS keychain and Windows device jobs stay private.

**Alternatives.** AGPL-3.0 protects the commercial layer more, but it deters company adoption,
and the pitch is that a team can read, install and embed the engine. A dual licence with a
source-available control plane only makes sense if the control plane ships, and it does not.
Making this repository public would publish customer names and the control plane, and a rewrite
of its history destroys the record without removing the control plane.

**Consequence.** The public and private copies of each shipped file are identical, so customer
names are replaced here, once. Each release, and each push to the public repository, runs gates
for names, secrets, private files and links. The hand port costs maintainer time for each outside
change. A cloud vendor may host the engine; the commercial layer makes that less attractive but
does not prevent it. Tests that need the control plane move to a private crate, so the SECURITY §7
rows they cover have no public test.

**Reverse it if** outside contributions grow until the hand port (D3) is the bottleneck.

---

## ADR-0040 — Cedar decides grants, from a fixed policy set

**2026-10-28 · Accepted** · plan not published, requested by the owner on 2026-10-23 · keeps ADR-0001

`zs_policy` decides every credential release from about 100 lines of hand-written matching over
`Policy`. ADR-0001 makes it the one evaluator in the control plane and in the agent, so a change
to its semantics is a change to the release path. The matching has no formal model: `permits`,
the environment check and the project check are three separate Rust predicates, and only a test
grid holds them in step. Cedar is a policy engine written in Rust with a formal semantics. It
keeps the single evaluator, and a later customer-written policy has a language to use.

**Decision.**
- **D1.** The public API is unchanged: `Policy`, `ResourcePolicy`, `GrantRule`, `Evaluation`,
  `PolicyDenied`, `evaluate`, `evaluate_in`, `evaluate_scoped`, `authorizes_project` and `permits`
  keep their signatures and their denial text. `wire_grant` puts that text in the 403 body.
- **D2.** The policy set is static: `crates/zs-policy/src/zerosecret.cedar` and
  `zerosecret.cedarschema`, loaded with `include_str!` and parsed once in a `LazyLock`. Policies
  written by a customer are out of scope and need their own spec.
- **D3.** The model is one namespace, `ZeroSecret`. A principal is `User::"<subject>"` with
  `grants: Set<GrantKey>` and `scopes: Set<ScopeKey>`; each grant rule adds one record per
  operation. A resource is `Resource::"<name>"` with `operations: Set<String>` and an optional
  `project`. The action is `Action::"use"`, and the context carries the request terms.
- **D4.** One `permit` carries the grant condition, so Cedar's default deny holds on its own.
  Four `forbid` policies name the reason: `environment`, `no-grant`, `resource-operation` and
  `project`. Each carries an `@id` that maps back to the reason.
- **D5.** A request is `Ok` only when Cedar allows it, its diagnostics hold no error, and the
  resource exists in the policy. Otherwise the reason is the first that applies in the current
  order: environment, no grant, unknown resource, resource operation, project.
- **D6.** `Evaluation.grant` is the first `GrantRule` in policy order whose subject, workload,
  resource, operations and environment match. The choice is made in Rust only after Cedar allows.
- **D7.** `permits` stays plain Rust. `zs-grant` calls it for every agent request, and the HTTP
  latency budget is under 6 ms p95. A test holds the Cedar `*` rule to the same answer.

**Consequence.** The API, the stored `Policy` JSON and every denial string stay the same, so
`apps/control`, the dashboard, the seed file and `zs-grant` are untouched. `zs-policy` gains a
dependency tree, which the agent's idle-RSS and cold-start budgets constrain. A policy written by
a customer still needs storage, an editor and a migration spec. The current evaluator stays as a
test-only reference, and a differential test compares the two over a generated grid.

**Reverse it if** a Cedar license, MSRV or maintenance change makes `cargo deny check` fail, or
the owner refuses the dependency tree.

---

## ADR-0044 — An audit record may name its credential source

**2026-10-28 · Accepted** · design `docs/specs/2026-10-24-credential-sources-design.md` §2.8, accepted by the owner 2026-10-24 · extends ADR-0032

The SSM spec (§5.5) asks that a grant and its materialization record the parameter and the role
ARN. The audit record had fixed fields, and the value of a credential must never enter it. An
operator who reads the journal needs to know which source produced a credential, not only which
resource used it.

**Decision.** `AuditRecord` and `AuditRequest` gain one optional field, `credential_ref`. The
display forms are `file:<reference>` and `aws_ssm:<role_arn>:<parameter>`.
- **D1.** The field is hashed only when present: the byte `0x01`, the value with `\0` replaced by
  U+FFFD, then the byte `0x00`, after the `reason` bytes.
- **D2.** The field is written to the journal, shipped with the record, and stored in
  `audit_records.credential_ref`.
- **D3.** The flow handler answers the reference from its cached grant. A deny with no grant
  records no reference.
- **D4.** A chain written before this decision has no such field and still verifies.

The value forms are identifiers. A parameter name and a role ARN are not secrets, and the
credential value never reaches this field.

**Alternatives.** A new record type for remote sources splits the chain and forces every reader
to handle two shapes. A free-text `reason` suffix hides the reference from queries and mixes it
with denial text. Both are refused.

**Consequence.** Audit readers and the control database gain one nullable column. An old agent
ships records without it, and the control store accepts them. The bracket byte keeps a reason and
a reference from hashing to the same bytes.

**Reverse it if** an external verifier must consume the chain and cannot accept an optional
field, or if the operator decides that a parameter name may not leave the agent. Then the field
moves to the diagnostic log only.

---

## ADR-0043 — The credential source is a typed, signed field; stores are routed by kind

**2026-10-28 · Accepted** · design `docs/specs/2026-10-24-credential-sources-design.md` §2.2–2.3, accepted by the owner 2026-10-24 · extends ADR-0038's signed grant

A signed grant named its credential as one free string, `credential_ref`. The AWS SSM spec
added a separate `aws_ssm` block to the policy and to the grant. A third store would have added
a third block in both places, a third branch in the materializer, and a third place where the
signed payload could drift.

**Decision.** The source is one typed field, `CredentialSource`, with two variants: `File` and
`AwsSsm`.
- **D1.** A `File` source serializes as `credential_ref` and signs exactly the bytes that grants
  signed before this change. A golden vector in `zs-grant` proves it.
- **D2.** A remote source signs four `source.*` records between `resource` and `subject`, in
  alphabetical order. A grant with both `credential_ref` and `source`, or with neither, is
  refused.
- **D3.** `materialization` stays signed, and the control plane and the agent both refuse a
  resource where it differs from `source.mode()`.
- **D4.** Stores are routed by `SourceKind` through a closed struct with an exhaustive `match`.
  A kind with no store denies. Nothing falls back to the file store.
- **D5.** The agent's own `zs-policy.json` accepts only a `File` source. A local file cannot
  point an agent at an AWS role, region or parameter.
- **D6.** One `validate` call runs on create, update, seed and grant mint.
- **D7.** An agent built before this decision cannot parse a grant without `credential_ref`, so
  it denies an AWS SSM grant. A test pins that.

**Alternatives.** One optional policy block and one grant field per store (the SSM spec as first
written) repeats the work for each store. A string-keyed store map or a plugin trait object makes
a missing key a silent fallthrough; a closed struct keeps denial exhaustive. Both are refused.

**Consequence.** A new remote store adds one enum variant, one registry field and one store
implementation. Every source change is a signed change, so an agent trusts only what the control
plane signed. The signed payload grows by four records for a remote source. Grants already in
flight keep their bytes.

**Reverse it if** the source list stops growing at two and the SSM block proves sufficient. Then
the enum and the registry hold one real remote case, and a single optional block would cost less.
The owner re-decides; this entry is not edited.

---

## ADR-0042 — Dashboard writes need the `admin` role, and reads need membership

**2026-10-23 · Accepted** · spec `docs/specs/2026-10-23-dashboard-write-roles.md` · spec approved 2026-10-23 · replaces the "Admin" ruling of ADR-0038

The dashboard is where an admin sets what the control plane signs: a resource's host and
connection (ADR-0038), its grant rules, and later its AWS SSM role and parameter. Before this
change, any identity that the IdP verified could change all of it. The recon on 2026-10-23
found these gaps:

- Every write checked a session and a CSRF token. No code read `members.role`.
- A session was created for any verified identity, member or not.
- Every dashboard page and write acted on the `default` organization with no membership check.
- `POST /approvals/{id}/approve` had no session check and no CSRF check.
- `POST /enrollment-token` took the organization from the form, so any session could issue a
  token for any organization.
- All dashboard GET pages, `/audit` and `/export/audit` (up to 10,000 rows) needed no session.
- `GET /approvals` listed the approvals of every organization.
- There was no first admin. Members were added only through `/members/create`.

**Decision.** The spec §3 has the full text of each item.
- **D1.** Roles are `admin` and `member`. An admin does every dashboard write. A member reads.
- **D2.** The first admins come from `ZS_CONTROL_ADMINS` at startup.
- **D3.** Any member reads every dashboard page, including audit and its export.
- **D4.** The role is read from `members` on every request. Nothing caches it, so a demotion or
  a removal applies to the next request.
- **D5.** The dashboard keeps acting on `default_organization()`. `ZS_CONTROL_ADMINS` makes
  admins in that organization.
- **D6.** `ZS_CONTROL_ADMINS` only adds. Removing a subject from the variable unpins it. Its row
  stays `admin` until an admin changes it.
- **D7.** A subject listed in `ZS_CONTROL_ADMINS` is pinned. The dashboard refuses to demote or
  remove it.
- **D8.** The dashboard refuses a demotion or a removal that would leave the organization with no
  admin.
- **D9.** Any member of organization X, admin or not, may issue an enrolment token for X. The
  token stays bound to the issuer's own subject (ADR-0036). A subject who is not a member of X is
  refused.
- **D10.** Approvals are organization-scoped. `pending_approvals` gains `organization_id`,
  `/wire/grant` writes the device's organization, the list shows only the dashboard
  organization, and approve is an admin write with a CSRF token.
- **D11.** A role other than `admin` or `member` is refused on write and refused by a database
  constraint. Existing values other than `admin` become `member`.
- **D12.** Members see the same pages without the forms. Forms and CSRF tokens are rendered only
  for admins, except the enrolment token form, which every member sees.
- **D13.** One subject rule serves `ZS_CONTROL_ADMINS` and the member forms: not empty after
  trimming, no control character, no comma, at most 320 bytes. The match is exact, case included,
  against the session subject (the `email` claim, else `sub`).
- **D14.** D7 and D8 apply to every path that can change or drop a role: `/members/create`,
  `/members/update` (a rename deletes the old row) and `/members/delete`. `role=admin` for a
  pinned subject is accepted.
- **D15.** The 403 "not a member" page carries the enrolment token form, limited to the
  subject's own organizations. A subject outside the dashboard organization can then still issue
  their own token.
- **Two additions from the build.** `/enrollment-token` refuses an `organization` that has a
  control character: 400 `organization has a control character`. `POST /approvals/{id}/approve`
  takes a form with a `csrf_token` field, so it goes through the same check as the other writes.
- **Replaces the "Admin" ruling of ADR-0038** (2026-10-21, below). In ADR-0038, "admin" meant
  anyone who can write to the dashboard. Now it means the `admin` role. ADR-0038 itself is not
  edited.

**Consequence.** A harness that drives the dashboard must start `control` with
`ZS_CONTROL_ADMINS` set to its sign-in subject. The dashboard pages need a sign-in, and a
subject that is not a member gets a 403 page. A store error or a missing database gives 503, and
it never lets a request through. If every admin is lost, the only way back is to set
`ZS_CONTROL_ADMINS` and restart `control`. A connection value is now as strong as the `admin`
role (SECURITY §3). The row set is in SECURITY §7. Dashboard changes stay `control:` lines and do
not enter the hash-chained audit journal.

**Not closed here.** The dashboard acts on one organization. `ZS_CONTROL_ORG` seeds the policy
for its own organization, and the dashboard still acts on `default`: this mismatch is an open
item, tracked outside the published docs. SECURITY §3 owns the other limits.

**Reversed by:** a dashboard for several organizations, or project-level roles.

---

## ADR-0039 — The proxy reads and writes HTTP/1 through hyper

**2026-10-23 · Accepted** · plan not published · replaces the `zs-mitm` exemption in ADR-0013

`zs-mitm` reads every HTTP/1 head itself, buffers the body, and writes the request again with its
own `serialize_request`. A forwarded request therefore carried
the proxy's header case and a fresh `Content-Length`, never the client's bytes, and 339 lines of
framing functions carried the chunked, length and head rules. The workload holds no signing
key, and since ADR-0035 the agent computes every signature it adds, so no supported scheme signs
the client's header order.

**Decision.**
- **H1.** hyper 1 `http1` reads and writes both sides. ALPN stays `http/1.1` on the client-facing
  TLS and on the upstream TLS; HTTP/2 waits for a spec that pins every `:authority` to the CONNECT
  target. The server builder sets `auto_date_header(false)`, because hyper adds `Date` and the
  proxy adds nothing.
- **H2.** Header names keep their case in both directions, through `preserve_header_case(true)`
  and `title_case_headers(true)` on both builders. The request's extensions reach the upstream
  request, and the order of distinct names may change. Values pass through unchanged, apart from
  the existing lossy replacement of a byte that is not UTF-8.
- **H3.** A request body is buffered whole up to `MAX_BODY` (32 MiB), because `Protocol::inject`
  and the signing schemes read all of it. A response body streams.
- **H4.** A request whose `Transfer-Encoding` is anything other than exactly one `chunked` is
  refused and the connection closes. hyper refuses the codings it will not frame before the proxy
  sees them; the proxy refuses the rest. Either way the reply is `400 ZeroSecret refused an
  ambiguous request`, and the diag code is `unsupported_coding` when the proxy decides it and
  `unparseable` when hyper does.
- **H5.** The fixed replies keep their status lines: `502 ZeroSecret denied`, `502 audit
  unavailable`, `502 upstream unreachable`, `400 ZeroSecret refused an ambiguous request` and
  `200 Connection established`. Each non-2xx reply carries `Content-Length: 0` and `Connection:
  close`, and the CONNECT-time deny keeps `502 <reason>`, with `ZeroSecret denied` when the
  reason is not a valid reason phrase.
- **H6.** The diag framing codes stay for the conditions the proxy still detects itself (H4 and
  `body_too_large`). A hyper parse error maps to `unparseable`, and a head over `MAX_HEAD` maps to
  the code `zs_diag::io_kind` returns for `ErrorKind::InvalidData`. A request line hyper refuses
  is logged as `conn_accepted` with `form` `unparseable` and its destination withheld, so the
  connection is still counted without the target reaching the log. An upgraded connection logs
  `conn_closed` from the tunnel task, with the code its inner connection ended on. A target whose
  fragment hyper would silently drop is refused before the service sees it, by a byte-level guard
  that follows `Content-Length` and chunk framing and fails closed when it cannot.
- **H7.** One tunnel keeps one upstream `SendRequest` and reuses it while it is ready. A reused
  connection that fails before the response head is retried once on a new connection, and a new
  connection that fails answers `502 upstream unreachable`. A retry never repeats a request that
  reached the upstream: only a request that was not written, or an idempotent method, is sent
  again.
- **H8.** A WebSocket upgrade uses hyper's upgrades on both sides, and `websocket::relay`
  (`crates/zs-mitm/src/websocket.rs:350`) receives the two `Upgraded` streams.
- **H9.** The `bytes` field of `response_relayed` counts response body bytes, where it counted
  head and body. The event is emitted when the body ends or is dropped.

**Consequence:** the 339 lines of hand-written framing functions go, with the unit tests that only
tested them, and `http1.rs` adds a byte layer of its own: builders, the fixed replies, the two
conversions and the guard for a `#` target. A request pipeline of `Authorize`, `Inject` and
`Forward` layers serves both entry points (`pipeline.rs`). HTTP/2 becomes a later spec.

What a workload or a diag reader can observe, beyond H2 and H9:
- A head hyper's parser refuses now gets hyper's own `400 Bad Request` or `431` instead of a
  silent close, and its diag code follows H6.
- A passthrough `CONNECT` to an unreachable host now gets `502 upstream unreachable` instead of
  `200 Connection established` followed by a close.
- A failed audit write on a refusal answers `502 audit unavailable` instead of dropping the
  connection.
- A retry writes one `upstream_failed` line with `stage=relay` before it succeeds.
- A fragment in a target is still refused, and an out-of-scope WebSocket upgrade still gets no
  credential.

**Reversed by:** a signing scheme the agent must support that signs the client's header order.

---

## ADR-0038 — The signed grant names the upstream connection

**2026-10-21 · Accepted** · spec `docs/specs/2026-10-21-signed-upstream-connection.md` · spec approved 2026-10-21 · replaces the `upstream_host` ruling of ADR-0037

ADR-0037 signs a resource's `host` and `protocol`, so a pull request to `zs-policy.json` cannot
point a binding at another host name. The binding still chose how the agent reached that host:
`upstream_host` on the `--enrollment-token` path, `upstream_port`, `upstream_plaintext`,
`upstream_ca`, `upstream_cert_sha256` and `local_endpoint`. A committed change to any of them
could send the credential to another server or port, turn TLS off, add a CA, pin a leaf, or open
a local endpoint. The owner treats all of these as equally serious (2026-10-21).

**Decision.**
- **Resource field.** `zs_policy::ResourcePolicy` has an optional `connection` block
  (`crates/zs-policy/src/lib.rs:27-28`). It is stored in the existing policy document, so there
  is no SQL migration. A document without it reads as the defaults:

  | Field | Values | Default |
  |---|---|---|
  | `upstream_host` | host name or IP literal | the resource `host` |
  | `upstream_port` | 1 to 65535 | https 443, http 80, postgres 5432, mysql 3306, mongo 27017 |
  | `upstream_tls` | `default`, `plaintext`, `ca-sha256:<64 hex>`, `pin-sha256:<64 hex>` | `default` |
  | `local_endpoint` | `true` or `false` | `false` |

- **One rule set (C7).** `Connection::validate` (`crates/zs-policy/src/connection.rs:190-234`)
  holds the rules. `upstream_host` is an IP literal (IPv6 with or without brackets) or a DNS
  name of letters, digits, `-` and `.`, at most 253 characters, with no empty label; a port,
  a space or a control character is refused. `ca-sha256` and `pin-sha256` are for postgres,
  mysql and mongo. `plaintext` is
  for mongo on any host, and for https when the upstream host is loopback. `local_endpoint` is for
  https. A protocol with no default port accepts only the defaults. The dashboard create and edit
  handlers (`apps/control/src/dashboard.rs:724`, `:881`), the seed file
  (`apps/control/src/main.rs:36-39`) and `wire_grant` (through `Connection::resolve`,
  `apps/control/src/wire.rs:332-342`) all call it.
- **Grant fields.** `zs_grant::Grant` has `upstream_host`, `upstream_port`, `upstream_tls` and
  `local_endpoint`, with no serde default (`crates/zs-grant/src/lib.rs:89-92`). The canonical
  payload keeps alphabetical key order: `local_endpoint` goes between `host` and
  `materialization`, and `upstream_host`, `upstream_port`, `upstream_tls` go between `subject`
  and `workload` (`:45-70`). The values are `true` or `false`, the host as is, the port in
  decimal, and the TLS mode in its string form. Hex is printed lowercase.
- **Resolved values (C3).** The control plane signs concrete values: `Connection::resolve`
  (`crates/zs-policy/src/connection.rs:236-250`) fills the resource `host` and the protocol's
  default port. An empty value never means "default" in a grant.
- **A protocol with no default port gets no grant (ruling 2026-10-21).** `resolve` refuses it,
  so `wire_grant` refuses it like an unknown resource. The agent gives such a protocol no handler
  anyway (ADR-0022). A new protocol must add its default port to `zs_policy::default_port`
  (`crates/zs-policy/src/connection.rs:122-136`).
- **An invalid stored connection signs nothing.** A policy document edited by hand can hold a
  connection that breaks a rule. `wire_grant` then answers 403 with the same body as for an
  unknown resource, `policy denied: unknown resource <name>`
  (`crates/zs-policy/src/lib.rs:63-67`), and prints
  `control: grant refused for <resource>: <reason>` (`apps/control/src/wire.rs:336-341`).
  `GrantMintRequest` is unchanged: the agent never sends its binding to the control plane.
- **Effective connection at startup (C5).** For each startup grant, on both the stored-enrolment
  and the `--enrollment-token` paths, `reconcile` (`apps/zs/src/connection.rs:185-236`, called
  at `apps/zs/src/run.rs:458-460`) runs before any listener and before the child. A file field
  that is set must equal the signed value. A field that is left out takes the signed value:

  | File field | Signed field | Equal when |
  |---|---|---|
  | `upstream_host` | `upstream_host` | ASCII case-insensitive |
  | `upstream_port` | `upstream_port` | equal |
  | `upstream_plaintext: true` | `upstream_tls` | `plaintext` |
  | `upstream_ca: <path>` | `upstream_tls` | `ca-sha256:H`, and the file's certificate hash is H |
  | `upstream_cert_sha256: <hex>` | `upstream_tls` | `pin-sha256:` with the same 32 bytes |
  | `local_endpoint: true` | `local_endpoint` | `true` |

  `upstream_plaintext: false` and `local_endpoint: false` are the serde defaults and count as
  not set. So a file cannot ask for TLS when the admin signed `plaintext`, or turn off a signed
  endpoint; neither gives the file more reach. A signed `ca-sha256` needs `upstream_ca` in the
  file, because the CA bundle stays a file in the repository.
- **Filled values are checked again (ruling 2026-10-21).** After `reconcile` fills the bindings,
  `zs run` runs the policy file's own validation again (`apps/zs/src/run.rs:484-488`). A filled
  value can break a file rule, for example two bindings whose filled `local_endpoint` gives the
  same environment prefix. The run then stops with a
  `zs: policy: <resource>: ... (after applying the control plane's signed connection)` line, so
  the line says that a signed value, not the file alone, caused it. The run-start `binding`
  diagnostic event is emitted after this fill, so its `upstream_override` and
  `upstream_plaintext` flags report the filled values (`apps/zs/src/run.rs:742`).
- **A binding with no startup grant.** Its effective connection comes from the file. Renewal
  skips a binding with no grant (`apps/zs/src/lib.rs:920-931`), so its requests are denied. The
  per-request check below still runs, as a guard for a later change that mints on a miss.
- **Renewal (C6).** The connection is fixed at startup. A renewed grant whose connection differs
  is skipped (`accept_renewal`, `apps/zs/src/lib.rs:898-906`), with the diagnostic failure
  `connection_mismatch`. The current grant runs until it expires, within 5 minutes. An admin
  change needs a restart of `zs run`.
- **Per request.** `authorized` (`apps/zs/src/lib.rs:958-959`) denies a request whose grant
  connection differs from the effective connection. This also runs in local mode against the
  file's grants.
- **Messages (spec 4.6, ruling 2026-10-21).** Startup lines name the file key that differs.
  Renewal and per-request lines name the signed field, so a TLS difference is `upstream_tls`
  there (`apps/zs/src/connection.rs:33-105`):

  | When | Text |
  |---|---|
  | Startup, a field differs | `zs: <resource>: <field> is <file value> in the policy file, but the control plane signed <signed value>; remove <field> from the policy file, or ask an admin to change resource <resource>` |
  | Startup, CA hash differs | `zs: <resource>: upstream_ca <path> has SHA-256 <file hex>, but the control plane signed <signed hex>; restore the file, or, if the new file is intended, ask an admin to set the resource's CA SHA-256 to <file hex>` |
  | Startup, CA signed, no `upstream_ca` | `zs: <resource>: the control plane signed a CA bundle with SHA-256 <hex>; set upstream_ca to that file` |
  | Startup, CA file unreadable | `zs: policy: <resource>: upstream_ca <path> cannot be read` |
  | Renewal | `zs: <resource>: the control plane changed <field> (signed <value>, running <value>); restart zs run to use it` |
  | Request | `<resource>: <field> differs from the grant`, for example `upstream_tls differs from the grant` |

  For a TLS field the startup signed value reads `upstream_tls <mode>`. `binding host does not
  match the grant` (ADR-0037) stays for `host` and `protocol`. A line prints hosts, ports, TLS
  modes, paths and SHA-256 hex only, never file content. An unreadable CA file keeps the existing
  load line (`crates/zs-upstream/src/tls.rs:29`, `apps/zs/src/lib.rs:609-610`), not spec 4.6's
  `zs: <resource>: cannot read upstream_ca <path>` (ruling 2026-10-21): the file is read once,
  at load, before any grant.
- **CONNECT port (C2).** For https and http, `classify` (`apps/zs/src/lib.rs:1005-1014`)
  intercepts a granted host on its effective `upstream_port` or on the protocol default (443,
  80), and forwards to the effective `upstream_host:upstream_port`. Any other port is denied with
  `port <n> is not the signed port <m>`. The default stays accepted because the harnesses send
  `https://<granted host>` on 443 to a signed loopback upstream. An absolute-form `http://`
  request to an https binding, or `https://` to an http binding, names port 80 or 443. So it
  gets this port deny unless its port is the effective `upstream_port` or the binding's
  protocol default (`apps/zs/src/lib.rs:1009`, ruling 2026-10-21).
- **CA hash (C9).** The hash is SHA-256 of the DER certificates in file order
  (`zs_upstream::load_ca`, `crates/zs-upstream/src/tls.rs:89-112`). Line endings, comments and
  whitespace do not change it; any change to the certificate set does. `AgentFile::load` reads
  the CA file once (`apps/zs/src/lib.rs:605-613`), and the trust store is built from the same
  parsed certificates (`UpstreamTls::from_loaded`, `apps/zs/src/lib.rs:232`). `zs ca-sha256
  <file>` prints the hash (`apps/zs/src/main.rs:411-426`). `shasum -a 256` of the file is not
  the value.
- **A signed CA adds to the public roots (ruling 2026-10-21).** As before, a `ca-sha256` CA is
  added on top of the bundled public roots (`client_config`,
  `crates/zs-upstream/src/tls.rs:128-139`). The signature covers what the file adds.
- **Dashboard (C8).** The create form and the edit row have upstream host, upstream port, a TLS
  mode select (default, plaintext, CA bundle, pinned leaf), a SHA-256 field and a local endpoint
  checkbox. Empty means default. The help text names `zs ca-sha256 <file>` and
  `openssl x509 -outform der -in <cert> | shasum -a 256`
  (`apps/control/src/dashboard.rs:131-164`). A rule failure answers 400 with the rule text. An
  edit that does not send the block keeps it (`:880`). When the stored policy document does not
  parse, every dashboard edit answers 500 and stores nothing, and `control` prints
  `control: dashboard edit refused: the stored policy of organization <org> does not parse`
  (`:648-682`); before, the edit replaced that document with one holding only the edit. A
  change prints
  `control: resource connection changed by <subject> resource="<name>"`
  (`apps/control/src/session.rs:614-619`).
- **Seed file (C10).** When `control` seeds an organization from `ZS_CONTROL_POLICY`, it
  validates each resource's connection and exits on an invalid one, naming the resource
  (`apps/control/src/main.rs:33-39`, `apps/control/src/state.rs:405-412`).
- **`zs resources` (ruling 2026-10-21).** It reads `run.control` from the policy file, like
  `zs status` (`apps/zs/src/main.rs:304-307`). With a stored enrolment it fetches
  `/wire/policy` and prints `connection (control plane, display only): <summary>`. Without one,
  when the fetch fails, or when that policy has no resource of the binding's name, it prints
  `connection: signed at run time`. With no control URL (local mode) it prints
  `connection: from the policy file (local mode)`
  (`apps/zs/src/main.rs:428-492`, `apps/zs/src/run.rs:119-140`). The policy response is not
  signed. Only the grant decides.
- **`upstream_host` with a stored enrolment.** This replaces ADR-0037's ruling. `zs run` accepts
  `upstream_host` on both paths when it equals the signed value, and stops with the field line
  above when it does not.
- **"Admin" (ruling 2026-10-21).** Dashboard write roles are not enforced (spec O6). Here,
  "admin" means anyone who can write to the dashboard, until the dashboard-roles spec lands.

**Compatibility.** `zs` and `control` ship from the same release (ADR-0036, ADR-0037). No
version field is added. A grant from an older `control` has none of the new fields: it does not
parse, and the agent refuses it. An older `zs` cannot verify a new grant, because its payload
lacks the new keys: it has no grant and fails closed. A stored resource has no `connection`
block, so it signs the defaults. After the upgrade, a binding that sets a non-default value
stops with the field line, which names the field, until an admin sets that value. An admin can
set the values before or right after the upgrade. A local-mode policy file's own `grants` need
the four fields and a new signature.

**Consequences.** With a control plane, a committed file cannot change the upstream host, port,
TLS mode, CA, pin or local endpoint. A file may leave these fields out and take the signed
values, so a reviewer cannot see the connection in the file alone; `zs resources` shows it.
A connection value is now as strong as dashboard write access, and every signed-in identity has
that until the dashboard-roles spec lands. An admin change needs a restart of `zs run`. A
workload that reaches a granted https or http host on an unusual port needs the admin to sign
that port.

**Not closed here.** `auth` stays unsigned, an accepted limit (owner, 2026-10-20). Dashboard
write roles are the next spec (O6). Local mode trusts the file's own keys and grants by design
and gets no protection from this check (ADR-0037). SECURITY §3 owns these limits.

**Reversed by:** a grant format that names a set of upstreams for one resource, or a signed
connection document separate from the grant.

---

## ADR-0037 — The signed grant names its host

**2026-10-19 · Accepted** · spec `docs/specs/2026-10-16-plain-zs-run.md` §5.4a · spec approved 2026-10-17

`zs_grant::Grant` named the resource and the protocol, but not the host. The binding in
`zs-policy.json` decided where the agent used a granted credential. ADR-0036 puts the run
settings into that file, and app repositories commit it. A pull request could then point a
binding at another host and receive the credential.

**Decision.**
- **Field.** `Grant` has `host: String` with no serde default. The control plane fills it from
  its resource row. The canonical payload adds `host` between `grant_id` and
  `materialization`. `protocol` was already signed.
- **Check.** The agent compares the grant's `host` and `protocol` with the binding's `host` and
  `protocol`, ASCII case-insensitively. At startup, a mismatch stops the run before the child
  starts, with `zs: <resource>: binding host does not match the grant`. At renewal, the agent
  prints a line and skips that renewal.
- **Compatibility.** A grant minted before this change has no `host`. It does not parse, and
  the agent refuses it. An agent built before this change cannot verify a grant from a new
  control plane, because its signed payload has no `host`: it fails closed as no grant. Upgrade
  `zs` with or before `control`. Since ADR-0036's `POST` claim, sign-in needs `zs` and
  `control` from the same release.
- **`upstream_host` (ruling 2026-10-19). Replaced by ADR-0038.** With a stored enrolment,
  `zs run` refused a binding that set `upstream_host`, before any network call and before the
  child started, and the `--enrollment-token` path kept `upstream_host`. That refusal line is
  removed. Since ADR-0038 the grant signs `upstream_host`, and on both paths a binding's
  `upstream_host` must equal the signed value.
- **File keys and grants (ruling 2026-10-19).** When a control URL is set, with a stored
  enrolment or with `--enrollment-token`, `zs run` refuses a policy file whose `signing_keys`
  or `grants` is not empty, before any request and before the child starts:
  `zs: signing_keys and grants in the policy file are not allowed with a control plane`.
  Local mode, with no control URL, keeps the file's keys and grants by design, with one
  exception (2026-10-20): a policy file with its own `signing_keys` or `grants` cannot choose
  `credentials_dir` (SECURITY §3, SECURITY §7 row 60).

**Consequences.** With a control plane, the control plane is the only source of grants and
of verifying keys, so every grant names a host from a control-plane resource row. With a
stored enrolment, `upstream_host` was also refused (until ADR-0038 signed it), so a committed
binding could not send a credential to a host name that the control plane did not name. One
resource has one host, so a resource that is reached at two hosts needs two resources. Local
mode trusts the keys in the file, so this decision gives it no protection.

**Not closed here.** The unsigned binding fields `upstream_port`, `upstream_plaintext`,
`upstream_ca` and `upstream_cert_sha256` stayed a documented limit for the owner to decide.
ADR-0038 signs them, with `upstream_host` and `local_endpoint`. What stays unsigned is in
[SECURITY.md §3](SECURITY.md#3-what-zerosecret-does-not-defend-against).

**Reversed by:** a grant format that names a set of hosts.

---

## ADR-0036 — SSO sign-in with membership enrols a device, and the enrolment row owns the subject

**2026-10-19 · Accepted** · spec `docs/specs/2026-10-16-plain-zs-run.md` · owner decisions 2026-10-16 · ruling 2026-10-19

ADR-0015 needs an operator token for each enrolment. So `zs run` against a control plane
needed a new `--enrollment-token` for each run, and the acme and globex harnesses minted one
for each run through the dashboard. `/wire/grant` took the subject from the request body. The
device signs the body, but the device chose the subject, so an enrolled device could ask for
grants as any member. `control` made a new grant-signing key at each start, so an enrolment
could not stay valid after a restart. The run settings had no place other than the command
line.

**Decision.**
- **Self-enrolment.** `zs login` makes a random 32-byte verifier and sends its SHA-256 as
  `GET /login?cli_challenge=<64 hex>&device=<name>`. After the OIDC sign-in,
  `POST /login/claim` with a form body of the state and the matching verifier returns the
  subject and a self-enrolment token. A `GET` gets 405, so `zs` never sends the verifier in a URL.
  The token is single use, has a TTL of 300 s and has no project. It is
  bound to the subject and to the organization of the subject's `members` row. `zs login`
  then enrols immediately through `/wire/enroll`.
- **Claim refusals.** A missing or wrong verifier gives 404 `no completed login to claim` and
  does not change the login. A subject with no `members` row gives 403 `not_a_member`. A
  subject with more than one gives 409 `several_organizations`. Both consume the claim. A
  dashboard login has no challenge and never gets a token.
- **Login code.** `zs login` prints the first 6 characters of the challenge in upper case, and
  the device name. The callback page shows `code <CODE> for device <NAME>`. The user compares
  the two.
- **Operator tokens.** A token from the dashboard is bound to the session subject of the
  operator who issues it. There is no free subject field.
- **Enrolment row.** Each enrolment, from either kind of token, writes `devices.subject` and
  `devices.expires_at_ms` (enrolment time plus 7 days).
- **`/wire/grant`.** The control plane checks the device signature and then the device row.
  These checks run before an approval request or a policy evaluation. A failure is 401 with
  the body `{"code": "<code>"}`: `device_unknown` (no row, no subject, bad key, missing or bad
  signature),
  `enrolment_expired` (no expiry, or an expiry in the past), `subject_mismatch` (the body
  subject is not the row subject), `not_a_member` (no `members` row in the device's
  organization). A policy denial stays 403.
- **Stored identity.** The TLS client key and the device signing seed are in one native record
  per enrolment. The public data is in `$ZS_HOME/.zs-device.json`. ARCHITECTURE §4 shows the
  layout. With a stored enrolment, `zs run` uses the enrolment's subject. At startup, a 401 from
  `/wire/grant` stops the run before the child starts.
- **Ruling (2026-10-19).** A `--enrollment-token` run also stops on a device-level 401 at
  startup, with `zs: control plane refused this device (<code>)`. So the subject of a harness
  needs a `members` row.
- **Ruling (2026-10-20).** On both paths, a transport error or a 5xx from `/wire/grant` at
  startup stops the run before the child starts, with
  `zs: control plane unavailable at <wire_url>; check the connection and retry`. At renewal, the
  agent keeps its cached grants until they expire.
- **Signing key.** `control` keeps its grant-signing key in
  `ZS_CONTROL_CA_DIR/control-signing.key`: 64 hex characters, mode 0600, created with
  `create_new`. A corrupt file is refused and kept. A symbolic link or a directory is refused.
  On Unix, an existing file whose mode gives any access to the group or to others is refused.
  The key id stays `control-k1`.
- **Run settings.** `zs-policy.json` has an optional `run` block with the keys `control`,
  `control_ca`, `credentials_dir`, `ca_dir` and `audit`. A flag wins over the file for each
  key. A `credentials_dir` from the file is limited. SECURITY §3 owns that rule and the trust
  boundary of these settings.

**What replaces the "human step" of ADR-0015.** For self-enrolment, the human step is the
`members` row. An admin adds the subject to one organization before the subject can enrol.
When the admin removes the row, every device of that subject stops at its next grant request.
The IdP sign-in proves the subject. The operator token stays as the other path, for harnesses
and for a subject in several organizations.

**What changes in ADR-0015.** SSO sign-in with membership is an accepted alternative to the
operator token. The local key generation, the client certificate, the operator token and
`/wire/enroll` stay as they are. New for both paths: each enrolment has a subject and expires
after 7 days.

**What changes in ADR-0016.** The decision stays: the key is delivered at enrolment and pinned
by key id. Two things are new. The agent keeps the pinned key in `.zs-device.json`, so the pin
lasts for the life of the stored enrolment and not for one run. The control plane keeps its key
across restarts, so the pin stays valid after a restart. With a stored enrolment, a grant that
does not verify with the pinned key stops the run at startup, with
`zs: control plane signing key changed; run zs login`.

**Upgrade.**
- The first start of `control` after this change makes a new signing key. Each device that
  enrolled before must enrol again, once.
- A token issued before this change has no subject. It no longer enrols: `/wire/enroll` refuses
  it with `401 enrolment refused` and the token is spent. Issue a new token.
- Since the claim moved to `POST /login/claim` (2026-10-20), `zs` and `control` must be
  upgraded together. An older `zs` sends a `GET` to a newer `control`, and a newer `zs` sends a
  `POST` to an older `control`. Each gets 405 and `zs login` stops with
  `zs: the control plane and this zs use different sign-in protocols; upgrade zs and control together`.
- `/wire/grant` refuses a device row with no subject (`device_unknown`). A device enrolled with
  a token that had no subject, between ADR-0036 and 2026-10-20, has such a row and must
  enrol again.

**Consequences.** A developer runs `zs login` once, then `zs run -- <cmd>` with no flags, until
the enrolment expires, an admin deletes the device, or an admin removes the membership. An
enrolled device cannot ask for grants as another subject. After a membership is removed,
grants that were already minted stay valid until they expire, at most 300 s. A self-enrolled
device has no project, so it reaches only unprojected resources (ADR-0021). A subject in
several organizations cannot self-enrol and needs an operator token. The login code does not
stop a user who ignores it (SECURITY §3).

**Reversed by:** a platform attestation mechanism that proves the device as well as the user,
or a need to approve each self-enrolment.

---

## ADR-0035 — Signing schemes re-sign on the agent, with a local endpoint and a presign answer

**2026-10-16 · Accepted** · no spec · owner decisions 2026-10-16 (all four gaps, the anonymous S3 passthrough, the b2 CLI binding)

initech signs its requests with two secrets that never go on the wire. A payment gateway wants
an HMAC-SHA256 `signature` header keyed with the API key. Backblaze B2 through the S3 API wants AWS
Signature Version 4. Bun's `S3Client` ignores `HTTPS_PROXY`, and initech gives presigned URLs to
browsers that never pass through the agent.

**Decision.**
- **`aws-sigv4`.** The binding names `access_key_id`, `region` and `service`. The client signs
  with a placeholder secret. The agent checks `x-amz-date` and `x-amz-content-sha256`, decodes
  a `STREAMING-` body before signing it, refuses a signed-header list without `host`, and
  computes the signature
  again with the real secret for the `Host` the upstream receives: the binding's host, with the
  port when it is not the default (the proxy writes that `Host` before signing; added
  2026-10-17). The `Credential` scope always comes from
  the binding, so the client cannot pick another key, region or service. The code matches the
  AWS reference vectors for a header-signed request and for a presigned URL.
- **Requests with no `Authorization` header.** `aws-sigv4` forwards them unchanged and adds
  nothing. This covers a presigned URL (the signature is in the query) and an anonymous read of
  a public object. Neither carries the secret, and the agent writes no credential into them.
- **The payment gateway's scheme** (renamed `hmac-body-signature` by ADR-0046). The agent
  computes `HMAC-SHA256(key, "METHOD:va:sha256hex(body):key")` from the `va` header and the body
  it forwards, and sets `signature`. A request without a body is signed over `{}`: the gateway
  accepts that for `GET /api/v2/payment-channels` and refuses an empty string or `[]` (live
  check 2026-10-17). A request without `va` is refused.
- **`local_endpoint: true`.** For an https binding, `zs run` opens a loopback HTTP listener and
  sets `ZS_<RESOURCE>_URL`. Each request on it is served as an absolute-URI request to the
  binding's origin, with the same grant, scope and audit path as the proxy.
- **`POST /.zs/presign`.** On the local endpoint only. The body is
  `{"url": <URL presigned with the placeholder>, "method": <method>}`. The agent checks the
  grant for that method and the binding's path scope, accepts only `AWS4-HMAC-SHA256`,
  `X-Amz-SignedHeaders=host` and `X-Amz-Expires` from 1 s to 15 minutes, signs again with the
  real secret, and answers with the URL on the binding's public origin. It never calls upstream.
  `X-Amz-Date` must be within 15 minutes of now, so the cap counts from the present.
  Audit: `presign <METHOD>`, allow or deny; a deny carries the reason (ADR-0032).
- **Endpoint origin check.** The local endpoint refuses a request whose `Host` is not
  `127.0.0.1:<port>` or `localhost:<port>`, or that has an `Origin` header. A web page that
  rebinds its name to the listener cannot use it.
- **Child environment.** `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` replace a
  client's trust store, and a passthrough host presents its real certificate. These three now
  name `ca-bundle.crt`: `ca.crt` followed by the roots of the parent's `SSL_CERT_FILE`, or else
  the first system bundle found (`/etc/ssl/cert.pem`, `/etc/ssl/certs/ca-certificates.crt`,
  `/etc/pki/tls/certs/ca-bundle.crt`). With no bundle found, they name `ca.crt` and `zs run`
  prints a warning. `NODE_EXTRA_CA_CERTS` adds to Node's roots, so it stays on `ca.crt`.
  `NO_PROXY` and `no_proxy` get `127.0.0.1,localhost,::1` added, because Bun sends loopback
  requests through `HTTP_PROXY` and would miss the local endpoint. `zs ca retire` also deletes
  `ca-bundle.crt`.

**Consequences.**
- initech needs `S3_CLIENT_ENDPOINT` for its S3 clients and `S3_PRESIGN_ENDPOINT` for presigning.
  `S3_ENDPOINT` keeps the public origin, because initech stores URLs built from it.
- A presigned URL outlives the grant. Revocation does not reach a URL already issued; it stays
  valid until its `X-Amz-Expires`, at most 15 minutes (SECURITY §3).
- Streaming SigV4 uploads are decoded and re-signed as a plain payload. For a `STREAMING-`
  `x-amz-content-sha256`, the agent decodes the aws-chunked body, sets `x-amz-content-sha256`
  to the SHA-256 of the decoded payload, removes `content-encoding`, and signs as it would any
  other body. Chunk signatures are the client's placeholders and are not verified. A trailer
  that carries an `x-amz-checksum-*` header has that header lifted into the request, and any
  other trailer name is refused. Bun's `S3Client` sends `UNSIGNED-PAYLOAD`; the AWS SDK v3
  sends `STREAMING-UNSIGNED-PAYLOAD-TRAILER` for a stream body and now works.
- The b2 CLI works through an existing `basic` binding on `api.backblazeb2.com`: the stored value
  is `base64(keyId:applicationKey)`. Later B2 calls use the returned token on passthrough hosts,
  which the new CA bundle makes trusted for Python.
- A child that relied on `SSL_CERT_FILE` naming only the agent CA now also trusts the system
  roots. Trust in the agent CA is unchanged.

**Reversed by:** a vendor that needs a signing scheme the agent cannot compute from the request
alone, or a decision to stop issuing presigned URLs from the agent.

---

## ADR-0034 — WebSocket bindings write the credential into one JSON field of client messages

**2026-10-16 · Accepted** · no spec · owner decision 2026-10-16

Runware's video API is a WebSocket. The client sends the API key inside its first JSON
message (`apiKey`), not in a header, so a header scheme cannot broker it.

**Decision.**
- **`websocket-json-field`.** The binding names one `field`. The agent accepts only a request
  with `Upgrade: websocket` on that host, relays the upgrade, then relays frames in both
  directions (`crates/zs-mitm/src/websocket.rs`).
- **Client to upstream.** The agent puts text messages back together and, in a JSON object or
  in each object of a JSON array, replaces the named string field with the credential. It
  never adds the field. Other frames go through frame by frame. A message over 32 MiB ends
  the session.
- **Upstream to client.** The agent holds each data message until its last fragment and writes
  it as one frame. It checks the message, the tail of the previous message, and every control
  frame (Close, Ping, Pong) before it writes them. One that carries the credential ends the
  session with audit `deny` `websocket message`, reason `websocket echo` (ADR-0032), and the
  workload never receives it. A message over
  32 MiB, a fragment out of order, a masked server frame or set reserved bits also ends it.
- **Held messages (added 2026-10-17).** While the stream ends with 8 or more bytes of the
  credential's start (half the credential if it is shorter than 16 bytes), the agent holds
  whole messages. The next message either completes the credential (the session ends as an
  echo, nothing held is written) or breaks the match (held messages go out in order). If the
  upstream ends or sends nothing for 5 s, the session ends with reason `websocket withheld`.
- **Each message.** Before the agent writes a message that carries the credential, it checks
  the grant again and writes the audit record (`websocket message`). A revoked or expired
  grant, or an audit write that fails, refuses the message and ends the session.
- **Bun.** Bun's `WebSocket` ignores `HTTPS_PROXY`. `zs run` writes `bun-preload.js` and adds it
  to `BUN_OPTIONS`; the preload routes `WebSocket` through the proxy.

**Consequences.**
- A server that echoes the key closes the session. A key split across separate messages lets
  at most its first 7 bytes reach the workload.
- A legitimate message that happens to end with 8 bytes of the key's start waits for the next
  message, up to 5 s, and then ends the session.
- Upstream messages are delivered whole, not streamed. A large message arrives only after its
  last fragment.
- Compression extensions are not negotiated, so frames stay readable.
- The preload is cooperative, like the Node preload (SECURITY §3). A workload that replaces
  `WebSocket` again opts out.

**Reversed by:** a vendor that puts the credential in a binary frame or a non-JSON message.

---

## ADR-0033 — Bindings may allow any HTTP method, and may use plain `http://`

**2026-10-16 · Accepted** · no spec · owner decision 2026-10-16

initech calls vendors with methods its bindings did not list (one vendor needs `HEAD`), and
another vendor is plain `http://` on a public IP. ADR-0026 allowed only listed methods and plaintext
only to a loopback upstream.

**Decision.**
- **`operations: ["*"]`.** `zs-policy::permits` treats `*` as every HTTP method, on the
  resource and in the grant, and `zs-grant::verify` uses the same check. `*` never names
  `connect`, so it cannot widen an L3 grant. A `*` binding under a grant that lists methods
  opens the host at CONNECT if the grant permits one of them; each request is then checked
  against its own method, so the grant's list still limits it (added 2026-10-17).
- **`protocol: "http"`.** The binding is plaintext to the upstream by explicit opt-in. `zs run`
  sets `HTTP_PROXY` only when such a binding exists. An `http://` request to an https binding,
  or an `https://` request to an http binding, is denied and audited. Audit records carry
  `protocol: http`. `upstream_plaintext` on an http binding is refused at load.

**Consequences.**
- On an http binding the credential crosses the network in cleartext. Anyone on the path can
  read and replay it (SECURITY §3).
- A `*` grant allows `DELETE` and every other method the vendor has. Use it only where the key's
  own vendor-side scope is the limit you want.

**Reversed by:** a decision that cleartext credentials are never acceptable, or that every
grant must list its methods.

---

## ADR-0032 — A deny record carries its reason in a hash-chained `reason` field

**2026-10-16 · Accepted** · spec `docs/specs/2026-10-16-audit-reason-field.md` · owner decisions 2026-10-16

Three proxy deny paths wrote the deny reason into `operation`; the other deny paths recorded
no reason. An admin could not filter by `operation` or see why most denies happened.

**Decision.**
- **Field.** `reason: Option<String>` in `AuditRecord`, `AuditIngestRecord` and the
  `audit_records` table. It is set on deny records only, and the JSON omits it when it is not
  set. `operation` is always the method, `connect`, or the protocol operation.
- **Hash.** Without a reason the hash input is unchanged, so existing journals verify. With
  one, the input ends with `0x00`, the reason and `0x00`. A NUL in a reason becomes U+FFFD; an
  empty reason is no reason.
- **Content.** Only text that the agent makes. A credential provider error is audited as
  `materialize failed` through an audit-only reason on `Denied`; the client still sees the
  provider text.
- **Compatibility.** Either the agent or the control plane can be upgraded first. A
  downgrade of the agent is one-way: an older agent reports `ChainBroken` on a journal with a
  reason, and `zs run` refuses to start until `.zs-audit/audit.jsonl` is moved.

**Not decided here.** A reason on allow records (for example the grant id), and a reason
filter in the dashboard and the export.

**Reversed by:** a decision to record the reason outside the hash chain, or to store the deny
reason in `operation` again.

---

## ADR-0031 — MongoDB gets an L3 listener that shows the driver a one-member replica set

**2026-10-11 · Accepted** · spec `docs/specs/2026-10-11-zs-proto-mongo.md` · owner decisions 2026-10-11

Acme keeps `MONGO_USER` and `MONGO_PASSWORD` next to its brokered credentials. ADR-0029 put
MongoDB after MySQL. A MongoDB driver with one seed and no `directConnection` reads the member
names from `hello` and connects to them directly, so a plain relay is bypassed.

**Decision.**
- **Shape.** `zs-proto-mongo` copies the MySQL L3 shape: one listener on `127.0.0.1:0` per
  binding, the grant check and the `connect` audit record before any upstream connect, a 15 s
  handshake, then a relay. `zs run` sets `ZS_<RESOURCE>_HOST` and `ZS_<RESOURCE>_PORT`.
- **Topology.** The agent rewrites every `hello` reply so that the set has one member: the
  listener. It routes each connection to the primary, with one redirect at most and only to a
  host in `hosts`. A per-listener primary state closes every connection pinned to an old
  primary, because the driver does not clear its pool after `NotWritablePrimary` on MongoDB
  4.2 and later. A new connection dials the known primary first.
- **Handshake.** The client's first `hello` is the upstream handshake, because the server
  refuses a second `hello` with client metadata (error 186). The agent sends it as `OP_MSG`,
  removes `speculativeAuthenticate`, `saslSupportedMechs` and `compression`, and adds
  `saslSupportedMechs` for the binding's user.
- **Authentication.** SCRAM-SHA-256 or SCRAM-SHA-1 only, with the binding's `user` and
  `auth_source` (default `admin`) and the brokered password. The agent never sends the password.
  It refuses a SCRAM-SHA-256 password that is not printable ASCII, an iteration count outside
  4096–1 000 000, a bad nonce, more than 3 continue rounds and a wrong server signature.
- **TLS.** MongoDB does not negotiate TLS, so a `mongo` binding uses TLS by default (webpki
  roots, `upstream_ca` or a pin). `upstream_plaintext: true` turns it off for any host. This is
  an exception to ADR-0026, which allows `upstream_plaintext` only for a loopback HTTPS
  upstream. The reason: SCRAM never sends the password.
- **Client refusals.** The agent refuses client `saslStart`, `saslContinue` and `authenticate`
  (error code 18, audit `deny` `authenticate`), and closes on `OP_COMPRESSED`, a checksummed
  message, a later `OP_QUERY`, another opcode, a frame that does not parse, and a frame
  outside the limits. SECURITY §7 rows 28–32.
- **Plan rulings.** Mongo diag events withhold the destination. The relay limit is the lower of
  the upstream `maxMessageSizeBytes` and 48 000 000. A SCRAM protocol failure answers the
  client with code 18. `AgentFile::load` applies the HTTPS loopback rule only to non-L3
  bindings.
- **Rulings made during the work.**
  - *Cached primary.* The agent checks only that the cached member is the writable primary.
    It does not remember the set name, which spec §5 asks for. Redirect discovery still checks
    the set name. The state holds one address. A cached address that moved to another set is
    very unlikely, and the agent still verifies its TLS and authenticates with SCRAM.
  - *Cached-primary limit.* The attempt on the cached primary has its own limit: one third of
    the handshake budget (5 s of 15 s). On timeout, the agent falls back to seed discovery.
  - *Generation number.* Spec §5 names a generation number. The `tokio::sync::watch` change
    notification is the generation. The code keeps no counter.
  - *Refusal reasons.* The `client_refused` reasons add `malformed` to the spec §10 list.
    A client `OP_MSG` that does not parse gets this reason. A SCRAM step from the server that
    does not parse gives `upstream_failed` with stage `auth` and kind `malformed`, and the
    client gets code 18.
  - *SCRAM rejection.* The agent emits `upstream_failed` with stage `auth` before it sends the
    code 18 reply (spec §10).
  - *`OP_QUERY`.* Every `OP_QUERY` other than a first-message `hello` on `<db>.$cmd` gets the
    `client_refused` reason `op_query`. This includes an `OP_QUERY` that does not parse and a
    later `OP_QUERY`.
  - *Duplicate keys.* `bson::Doc::set` drops later duplicates of a key. A duplicate field in a
    server reply therefore cannot keep an upstream address after the rewrite.
  - *CI.* The real-server tests run in the CI `db-real` job, through the compose service.
  - *Auth command during a reply (M-3, accepted 2026-10-16).* When a client sends
    `saslStart`, `saslContinue` or `authenticate` after the handshake, the relay stops both
    directions. If a server reply was in transit to the client, the code 18 refusal can follow
    a partial reply frame, and the client then reads a broken frame instead of code 18. The
    audit `deny` `authenticate` record and the `client_refused` event are written first, the
    command never reaches the server, and the connection closes in both cases. Drivers
    authenticate once, at connect, so this needs a client that authenticates again while a
    reply streams. A fix needs shared state between the two relay directions. Not done.
  - *SCRAM derivation (M-4, fixed 2026-10-16).* The upstream sets the iteration count, up to
    1 000 000. The derivation runs in `spawn_blocking`, as in PostgreSQL, so a login does not
    stall other connections on the runtime worker. No salted-password cache.

**Consequences.**
- Reads from secondaries go to the primary. `readPreference: secondary` fails server selection.
- A step-down gives the app a few network errors while the driver reconnects.
- If the seed is down and no primary is known, new connections fail.
- Each driver connection (monitor, round-trip, pool) is one upstream connection with its own
  SCRAM exchange and one audit record.
- `mongodb+srv`, load-balanced mode, x.509, LDAP, Kerberos, `MONGODB-AWS` and OIDC are not
  supported.

**Reversed by:** a decision to give each replica-set member its own listener, or to require
`directConnection` in each client.

---

## ADR-0030 — PostgreSQL upstream TLS, and `zs-upstream` holds the shared connect and TLS code

**2026-10-09 · Accepted** · from the globex staging smoke test · owner decisions 2026-10-09

The PostgreSQL L3 listener connected to the upstream in plaintext, always. Every query,
every result row and the SCRAM exchange crossed the network unencrypted. Nothing proved the
server to the agent except the SCRAM server signature. ADR-0026 says that the PostgreSQL
listener has "the same loopback exception" as HTTPS. The code did not do this. The listener
had no rule for the upstream connection. It sent plaintext to every upstream address. Its
only loopback rule, `SslPolicy::RefuseOnLoopback`, is on the client connection: it answers `N`
to the client's SSLRequest. This entry corrects that claim, and ADR-0026 now points here.
MySQL already verified its upstream with `UpstreamTls` (ADR-0029).

**Decision.**
- **Handshake.** After the TCP connect, the listener sends the 8-byte SSLRequest and reads
  exactly one byte. `S`: a TLS handshake, then the startup packet, SCRAM-SHA-256 and the
  relay inside TLS. `N` and no TLS field: plaintext. `N` and `upstream_ca` or
  `upstream_cert_sha256`: refuse. Any other byte, or a byte after `S` before the handshake:
  refuse (CVE-2021-23222 class). A TLS failure refuses the session. The listener never tries
  again in plaintext. One 15 s budget covers the TLS negotiation and the upstream login.
- **Verification.** The ADR-0029 rules. No field: the webpki roots and the name.
  `upstream_ca`: the webpki roots and these certificates, and the name. `upstream_cert_sha256`:
  the exact leaf and the handshake signature only. The name is `upstream_host` when it is
  set, else `host`.
- **CancelRequest.** The same negotiation as a session. It carries no password.
- **Configuration.** `upstream_ca` and `upstream_cert_sha256` are valid on `postgres`
  bindings. `client_auth_plugin` stays MySQL only. `upstream_plaintext` on a `mysql` or
  `postgres` binding stops `zs run` at load. `AgentFile::load` checks the CA file and the pin,
  so a bad value stops `zs run` before the child starts.
- **Client text and diag.** Every TLS refusal sends `upstream TLS failed`, SQLSTATE 08006.
  The causes are: a failed verification or pin, `N` when a TLS field is set, a bad answer
  byte, a byte after `S`, and a close or reset during the TLS handshake. An I/O error in the
  SSLRequest exchange, a close that the agent sees after `S` and before the handshake, and a
  timeout at any point of the TLS negotiation send `upstream unavailable`, SQLSTATE 08006.
  Three causes send `upstream authentication failed`, SQLSTATE 28000: an authentication
  refusal (SQLSTATE class 28), a SCRAM failure, and a method other than SCRAM-SHA-256.
  Another ErrorResponse keeps the server SQLSTATE and sends
  `upstream refused the connection`. The exceptions are SQLSTATE classes 08, 53 and 57, and
  a missing or malformed SQLSTATE. These send `upstream unavailable`. A timeout in the login also sends `upstream unavailable`.
  Diag has `tls` (`result` `verified`, `pinned`, `not_offered` or `failed`) and
  `upstream_failed` with stage `tls`. A failed `tls` event and `upstream_failed` carry a
  fixed `kind` and no server text. `upstream_auth_failed` gets `method` (`md5`, `cleartext`,
  `other`) when the server asks for a method other than SCRAM-SHA-256. The ADR-0028
  `server_text` on `upstream_auth_failed` does not change.
- **Shared code.** The new crate `zs-upstream` holds `UpstreamEndpoint`, `UpstreamTls`,
  `client_config` and `UpstreamTls::server_name`. `zs-proto-mysql` and `zs-proto-postgres`
  re-export the types. This replaces the ADR-0029 plan to extract the shared code in the
  MongoDB spec.

**Consequence.**
- Behaviour change: a `postgres` binding to a server that offers TLS with a private CA, for
  example every AWS RDS server, now refuses until it sets `upstream_ca` or a pin. Before, the
  agent connected in plaintext. The refusal is the fail-closed result.
- For RDS behind a DNS alias, set `upstream_ca` to the RDS bundle and `upstream_host` to the
  RDS endpoint name from the server certificate (README). The pin is the fallback.
- A server that answers `N`, with no TLS field, stays plaintext. An active attacker can
  remove the `S` (SECURITY §3).
- The upstream login stays SCRAM-SHA-256 only, with no channel binding. An md5 role fails,
  and diag shows `method` `md5`. A server that sends AuthenticationOk at once (trust) also
  fails, with `method` `other`.
- The materializer's admin connection (`zs_proto_postgres::execute_statement`) still
  connects in plaintext. It is outside this decision.
- The test `mysql_binding_fields_are_checked_at_config_load` in `apps/zs/tests/mysql_l3.rs`
  no longer lists a `postgres` binding with `upstream_cert_sha256` as an invalid config.
  That config is valid now.
- `Cargo.lock` adds only `zs-upstream`. The CI job `mysql-real` becomes `db-real` and also
  runs the PostgreSQL TLS tests. `tools/mysql-test-certs.sh` becomes a wrapper for
  `tools/db-test-certs.sh`.

**Reversed by:** a decision to refuse plaintext unless `upstream_ca` or the pin is set, or
direct TLS negotiation (`sslnegotiation=direct`) as the only mode.

---

## ADR-0029 — MySQL, MongoDB and Redis are scheduled, and MySQL gets an L3 listener

**2026-10-07 · Accepted** · from the acme coverage gaps and the customer's wider adoption · owner decisions 2026-10-03

Acme keeps `DB_PASSWORD` and `MONGO_PASSWORD` next to its brokered HTTP credentials, so acme
is not secretless under `zs run`. The customer plans to run more services under `zs run`, and they
use MySQL, MongoDB and Redis credentials. ROADMAP put these three protocols in "Deliberately
unscheduled", because each phase had to be a customer conversation. For these three, that
condition is now true: a customer exists and acme is the first workload.

**Decision.**
- **Roadmap.** MySQL, MongoDB and Redis move to v2. Each one gets its own spec, plan and
  review, in this order. The other unscheduled items stay unscheduled.
- **Shape.** `zs-proto-mysql` copies PostgreSQL L3. Each binding gets a listener on
  `127.0.0.1:0`. The agent checks the grant and writes a `connect` audit record before it
  connects upstream. The handshake has 15 s. Then the agent relays bytes. `zs run` sets
  `MYSQL_HOST` and `MYSQL_TCP_PORT` for the first MySQL binding, and `ZS_<RESOURCE>_HOST` and
  `ZS_<RESOURCE>_PORT` for every L3 binding.
- **Client leg.** The agent sends its own greeting. It has the upstream version, connection
  ID and capabilities without the TLS, compression and multi-factor flags, and a new scramble.
  The greeting names `caching_sha2_password`. A binding can set `client_auth_plugin` to
  `mysql_native_password` for an older client (owner decision 2026-10-06; this replaces the
  first spec draft's fixed `mysql_native_password`). The agent ignores the client's auth data and never
  asks the client to switch methods. It refuses a client that asks for TLS or compression.
- **Upstream auth.** The agent answers `mysql_native_password` and `caching_sha2_password`
  challenges with the brokered password. It sends the password itself only inside verified
  TLS (`caching_sha2_password` full auth, `sha256_password`, `mysql_clear_password`). It never
  asks for the server's RSA key. If the greeting names another plugin, the agent answers with a
  `mysql_native_password` scramble. It refuses an AuthSwitch to any other plugin, and more
  than 3 auth rounds.
- **Upstream TLS.** The agent uses TLS when the server offers it. It verifies the server with
  the webpki roots and the binding's `upstream_ca`. `upstream_cert_sha256` pins the leaf
  certificate of a server that has a self-signed certificate. A TLS failure refuses the
  connection; the agent never falls back to plaintext. `upstream_ca` or the pin without a TLS
  offer also refuses.
- **Re-authentication.** The relay refuses `COM_CHANGE_USER`, writes `deny change_user` to
  the audit, and closes the connection. If the audit write fails, the agent still refuses and
  closes. It writes one stderr line, and the diag event has no `audit_seq`.
- **Diagnostic events.** `upstream_failed` has stage `handshake` when the 15 s budget runs
  out. It has `errno` when the server sends ERR instead of its greeting. `materialized` has
  `deny_kind` `audit_unavailable` when the audit sink fails. `change_user_refused` has
  `audit_seq` when the audit record exists. `conn_closed` has `closed_by` `client`,
  `upstream`, `change_user`, `refused` or `timeout`.
- **TLS close.** On the TLS leg, an upstream close without a close_notify is a clean upstream
  close. MySQL closes the TCP connection without a TLS close_notify. It is not `upstream_failed` with stage `relay`.
- **Shared code.** `UpstreamEndpoint` and `UpstreamTls` live in `zs-upstream` (ADR-0030).

**Consequence.**
- With the acme launch wrapper (plan Tasks 11-12), acme's MySQL traffic runs with no
  `DB_PASSWORD` in acme. Acme reads `DB_PORT` and
  `DB_REPLICA_PORT`, and a launch wrapper copies the `ZS_*` variables into them.
- The agent refuses every connection to a MySQL 8 server that uses its auto-generated
  certificate, until the operator sets `upstream_cert_sha256`. That certificate has no name
  that the agent can verify, even with `upstream_ca`.
- On plaintext, a `caching_sha2_password` user can log in only by the fast path. Full auth
  on plaintext is refused.
- A client library that cannot use the greeting's method needs `client_auth_plugin`. The
  `db-real` CI job logs in with the `mysql` CLI from 5.7, 8.0, 8.4 and 9 under both
  greetings and prints the result.
- An upstream I/O error after login is logged as `upstream_failed` with stage `relay`
  (owner decision 2026-10-06).
- On plaintext, an active attacker can act as the server and take the session, but cannot
  get the password (SECURITY §3).
- One new direct dependency: `sha1 0.10`. It was already in `Cargo.lock`.
- The SHA-1 and SHA-256 crates in `Cargo.lock` (`sha1` 0.10.7, `sha2` 0.10.9, `digest` 0.10.7)
  do not zeroize their block buffers. Hasher state and finalize copies can keep
  password-derived bytes in memory until other data overwrites them. The 0.11 crates fix
  this. That is a dependency change, and this plan forbids it.
- `upstream_cert_sha256` compares the exact leaf certificate. It does not check the name, the
  chain or the validity dates, so an expired pinned certificate is still accepted. The TLS
  handshake still proves that the server has the private key of the pinned certificate.

**Reversed by:** an IAM token flow that removes the database password, or a decision to
refuse plaintext unless `upstream_ca` is set (spec §11).

---

## ADR-0028 — Every `zs run` writes a typed diagnostic log, separate from the audit journal

**2026-10-03 · Accepted** · spec `docs/specs/2026-10-03-zs-diag-diagnostic-log.md`

When `zs run` failed, the evidence was not enough. `zs-proto-postgres` dropped every connection
error, and the HTTP proxy wrote three fixed stderr lines. The owner wants one file per run
that a person or an LLM can read to find a bug.

**Decision.**
- **Crate.** A new crate, `zs-diag`, with no `zs-*` dependency. Protocol crates use it without
  a dependency on the audit journal.
- **File.** One JSON Lines file per run, in `.zs-log` next to the audit directory, or at
  `--log <path>`. Always on. Mode 0600 in a 0700 directory. The 10 newest runs are kept.
  50 MiB cap. No pruning with `--log`. `--log` appends, and the cap is per run.
- **Content.** Typed values only: fixed codes, numbers, flags, `Token` (a restricted
  character set, plus a lone `*` for the any-method operation, added 2026-10-17), and server
  error text during a handshake that is checked against the
  credential. Never a credential, a request path, a query string, a header value, SQL text, a
  body, argv after argv[0], an environment value or the subject.
- **Failure.** Best-effort. A full queue drops events and counts them. An unwritable location
  gives one stderr warning. Traffic never waits for the log and is never denied because of it.
  The audit journal keeps its fail-closed rule.
- **Join.** An HTTP event names its audit record with `audit_seq`. A PostgreSQL event has no
  `audit_seq`. A reader joins it to the journal by `ts_ms` and `resource`.
- **Events added 2026-10-28** (credential-sources Phase B). `materialize_failed` (component
  `agent`, warn) has `resource` and `error.kind`: `file`, `no_store`, `no_identity_token`,
  `refused`, `transport`, `session_expired`, `invalid_value`, `source_mismatch` or `exchange`.
  It has no reason text. `run_started` also has `test_endpoints` (flag: the binary was built
  with `cfg(zs_test_endpoints)`) and `test_resolve` (the count of `ZS_TEST_AWS_RESOLVE`
  overrides that the agent read; 0 in a build without the cfg, so in every release build). The
  PostgreSQL, MySQL and MongoDB `materialized` events take `deny_kind` from
  `zs_protocol::DenyKind`: `materialize`, `audit_unavailable` or `policy`. PostgreSQL can now
  give `audit_unavailable`; before, it always gave `materialize`. `zs run` never gives
  `policy`; only a materialize function that sets no kind gives it.

**Consequence.**
- A failed PostgreSQL handshake now leaves its SQLSTATE and failure kind.
- A refused HTTP request leaves the rule that fired.
- Hostnames and resource names leave the machine when the owner gives the file to an LLM.
- `zs run` handles no signals. Ctrl-C, SIGTERM, SIGKILL or OOM leave no `child_exited` or
  `run_ended`. A reader treats a missing `run_ended` as "the run was killed", and skips a last
  line that does not parse.

**Reversed by:** a requirement to ship diagnostic events to the control plane, which would need
a retention and access decision, or a requirement to capture traffic, which PRODUCT §3 rules
out.

---

## ADR-0027 — A binding's `paths` limits credential release; other paths pass through

**2026-10-06 · Accepted** · from acme integration note 4 (H12) · spec
`docs/specs/2026-10-03-per-path-injection-scope.md`

Acme uses one auth host for two jobs. Acme's own token exchange needs the brokered client
credentials. `checkClientAuth` sends the caller's own bearer token. Host-wide injection
replaced the caller's token, so auth refused every caller.

**Decision.**
- **Location.** An HTTPS binding can list `paths`. The list is in the local binding, not in
  the signed grant. It only limits release: without it, the agent injects on every path,
  which the grant already authorizes (ADR-0017).
- **Matching.** Exact, case-sensitive, byte-for-byte. The query is not matched. An entry
  has no `%`, `?`, `#` or `*`. A later prefix form is additive.
- **Ambiguity.** The agent never rewrites a path. On a binding with `paths`, it refuses,
  with `400`, a path that two parsers can read differently. The path is the part before the
  first `?`. The refused forms are: dot segments, `//`, `;`, `\`, `%2F`, `%5C`, `%2E`,
  `%25`, `%3B`, `%3F`, `%23`, a control byte, a non-ASCII byte, a bad escape, or a target
  that is not origin-form. The agent also refuses a fragment anywhere in the target. It does
  not validate the query otherwise. A binding without `paths` injects on every target. The
  agent writes `deny` with the method.
- **Outside the scope.** The agent forwards the request through the MITM without a
  credential and with the client's headers. It needs no grant and does not materialize. It
  writes `passthrough` with the method.
- **Methods.** `operations` applies to in-scope paths only.
- **Origin.** On every intercepted request, the agent sends one `Host` header. In absolute
  form, it comes from the URI authority. In a tunnel, it comes from the CONNECT authority.
  In a tunnel, the agent refuses a request whose `Host` or target names another origin. It
  writes `deny` with the method.
- **Config.** A binding refuses unknown fields. An empty or invalid `paths`, or `paths` on a
  non-HTTPS binding, stops the load.

**Consequence.**
- Acme-auth becomes `paths: ["/oauth/token"]`, `operations: ["POST"]`.
- For a scoped binding, an expired or revoked grant gives a per-request `deny` with the
  method. The CONNECT-time `deny` with the reason text does not occur.
- The dashboard does not show the scope.
- A client that sends `;`, `%2F` or `//` to a scoped binding gets `400`.

**Reversed by:** an operator requirement to limit a credential to paths that the developer
cannot widen. Then the grant carries paths too, and the agent injects only on a path in
both sets.

---

## ADR-0026 — Grants name methods, renew under the refresh loop, and reach upstreams only over TLS

**2026-10-03 · Accepted** · from the acme E2E findings (H1, H4–H6, H8–H11) · owner go-ahead 2026-10-03

The acme run put a real Node server behind `zs run`. Every POST failed, and every grant
expired 5 minutes into the session. A GET-only grant also let POST and DELETE through.
An `https://` origin on a port other than 443 got its credential in cleartext.

**Decision.**
- **Methods.** A binding lists its `operations` (default `["GET"]`). The agent requests a
  grant for all of them. It checks the real request method against the signed grant on
  every request. A method that the grant does not name is denied and audited with its
  method.
- **Upstream TLS.** The upstream hop is always TLS. Plaintext needs
  `upstream_plaintext: true` on the binding, and only a loopback upstream may set it. Any
  other upstream fails at config load. The PostgreSQL upstream rule is ADR-0030.
- **Renewal.** Each refresh tick (60 s) re-mints a grant that has 150 s or less left.
  A revoked grant is never renewed. A renewed grant keeps the IDs of the grants it
  replaced, so revoking any ID in that chain stops the session.
- **Operator revocation.** `POST /grants/revoke` on the dashboard takes a grant ID, with a
  session and CSRF token. Running agents deny within one refresh.
- **HTTP framing.** The proxy reads the request head through a buffer, so a body that
  arrives with the head stays a body. A chunked request body is decoded. The upstream gets
  exactly one `Content-Length` and never the client's `Transfer-Encoding`. The proxy refuses
  conflicting lengths, any coding other than `chunked`, and bodies over 32 MiB. An
  absolute-form connection serves requests until the client or the upstream closes it.
- **Node.** `zs run` sets `NODE_USE_ENV_PROXY=1`. The preload finds `undici` from the entry
  script's directory first, then from the working directory.

**Consequence.**
- A binding that omitted methods it needed now fails closed on the first other method.
  Acme needs `["GET", "POST"]` for auth and two other internal services.
- A test or a local fake upstream must opt in to plaintext.
- A session lasts as long as policy allows, not one TTL. Deleting a policy rule or a device
  ends it within one TTL after the next failed renewal.
- Revoking a grant ID ends it within one refresh.
- An operator finds the grant ID in the agent's `zs: grant` and `zs: renewed grant` lines.
  The dashboard does not list minted grants.

**Reversed by:** a policy model where the control plane, not the binding, chooses the
operations to mint. Or a minted-grant registry, which would let the dashboard list grants
and revoke them by session.

---

## ADR-0025 — The macOS lock check denies by its bound, not by exit status

**2026-10-02 · Accepted** · amends ADR-0024 · from CI run 36969175191

ADR-0024 expected `security show-keychain-info` to exit 36 (`errSecInteractionNotAllowed`)
on a locked keychain, with the bound as a fallback. On GitHub `macos-latest` it does not
exit at all: it blocks, most likely on an unlock prompt, until the 5 s bound kills it.

**Decision.** Keep the check. A check still running at its bound is a locked keychain, as
ADR-0024 already specified. A locked load or retire therefore denies with `secure CA
storage locked` after about 5 s, not at once. The agent waits on that prompt for at most
the check's bound, never for the 30 s per-call bound.

**Consequence.** Every locked start costs about 5 s. An unlocked keychain answers in
milliseconds (16 ms in CI), so a false "locked" needs a check slower than 5 s. On an
attended Mac the prompt may show for up to 5 s, and unlocking in that time lets the start
continue. That part is unobserved, because the runner has no UI.

**Reversed by:** an unlocked keychain whose check regularly takes more than 5 s, or a
non-prompting lock probe that a later `security` adds.

---

## ADR-0024 — A CA record is deleted only by `zs ca retire`, and a locked keychain fails fast

**2026-10-02 · Accepted** · amends ADR-0023 · owner decision 2026-10-02

ADR-0023 left two owner items open. A record outlived its CA directory: the agent never
deleted one, so the owner removed it by exact name with shell commands. And a locked macOS
keychain held each `security` read or write on its unlock prompt, so an unattended start
denied only after the fixed 30 s bound.

**Decision.** `zs ca retire --ca-dir <dir> --yes` is the one product path that deletes a
native CA record. It has no default directory, and it needs `--yes`. The delete is
conditional:
- it runs under the directory lock;
- it refuses while a legacy key copy exists (`ca.key.pem`, or the macOS pre-record item);
- it reads the record named by `.ca-storage-id`, decodes it, and requires it to match
  `ca.crt` when that file exists;
- after the delete, the record must read as absent.

Only then does it remove `ca.crt` and `.ca-storage-id`. Every failure is a fixed message. A
failure before the delete changes nothing. `zs run` still never deletes a record.

On macOS each load and retire first runs `security show-keychain-info`, bounded to at most
5 s. A locked default keychain, or a check still running at that bound, denies with `secure
CA storage locked` before the CA directory is created or locked. The agent never waits on
an unlock prompt. On Linux the same check of the default collection gives the same
message. The per-call
bound defaults to 30 s, and `ZS_KEYCHAIN_TIMEOUT_SECS` sets it to 1–300 whole seconds. Any
other value denies with `CA storage timeout invalid`, which never echoes the value.

**Consequence.** Retiring a directory loses its CA for good: every client that trusts its
`ca.crt` must trust a new one. The native stores have no compare-and-delete, so the record
read and the delete are two calls. Only a same-user writer that is not `zs` can act between
them (SECURITY §6). Records of directories that were deleted without retire stay orphaned.
Retire cannot name them, because their `.ca-storage-id` is gone. The README's exact-name
commands remain for them. An attended macOS user now unlocks the keychain, for example
with `security unlock-keychain`, and retries, instead of answering a prompt mid-start.

**Reversed by:** evidence that `show-keychain-info` prompts or succeeds on a locked
keychain, which would remove the fast denial. Or a native adapter with compare-and-delete,
which would make the retire delete atomic.

---

## ADR-0023 — The local CA key lives only in native secure storage, under a public directory ID

**2026-09-21 · Accepted** · recorded 2026-10-01 from native evidence

The agent's local CA key signs a certificate for every host the agent intercepts, so a
readable copy is the agent's whole interception authority. Before this decision only macOS
kept it out of the CA directory, in a Keychain item named by a digest of the directory
path. Linux and Windows kept `ca.key.pem` in the directory, at mode 0600 on Linux and with
no equivalent restriction on Windows. The [CA storage
design](specs/2026-09-18-platform-ca-storage-design.md) gives machine-local persistence to
this file.

**Decision.** The shipped agent keeps the CA key only in the platform's native secure
store: the default keychain on macOS, the Secret Service default collection on Linux, and
Credential Manager with `CRED_PERSIST_LOCAL_MACHINE` on Windows. There is no plaintext
fallback and no opt-in. Any other platform fails before the child starts.

Each CA directory has one native record. Its service is `zerosecret.ca.v1`. Its account is
a random 128-bit ID in the public `.ca-storage-id` beside `ca.crt`, not a path digest, so a
record belongs to the directory that holds its ID file and not to whatever later occupies
the path. The record is a versioned binary record of at most 2,560 bytes that holds the
certificate and key PEM. The agent writes a record only after it reads that none exists.
The write is natively create-only on macOS; on Linux and Windows it follows an absence read
under the directory lock, with the race that SECURITY §6 names. The agent never deletes a
record; its only delete is a validated legacy copy after migration.

**Consequence.** Every installation that runs the agent now holds this layout. A later
change of store, service name, account binding or record version must migrate from it with
the same validated-readback order, never replace it silently. Records outlive their
directories until an approved conditional-delete design exists, so the owner removes them
by exact name. A host without a usable native store cannot start the agent; a headless or
WSL Linux host without a Secret Service is the common case. A native Keychain API adapter
on macOS would change the adapter only, not this layout. Limits are owned by SECURITY §6.

**Reversed by:** a supported deployment target that has no native secure store and must
still run the agent. That needs a separately designed protected store with the same
fail-closed contract, not a plaintext key file. Evidence that a store cannot tell absence
from unavailability would also reopen this, because fresh creation depends on that
distinction.

---

## ADR-0022 — Strictness is a property of interception, not of materialization

**2026-09-18 · Accepted**

PRODUCT §7 defines strict mode as *the workload gets access without receiving the upstream
credential* — a question about **who holds the credential**. The implementation answered a
different question, *which materialization mode was used*, labelling `exchange` strict and
`retrieve` not. Those two questions come apart, and `zs resources` reported every HTTPS
resource — including the v1 demo resource — as `not-strict` for a property it did have.

Both interception layers present the credential themselves. `zs-mitm` terminates TLS and
injects the header on the upstream leg; `PostgresListener` completes SCRAM upstream and then
relays. The workload holds nothing in either case, whatever the mode. The L3 case is
load-bearing evidence because it is already a published claim: PRODUCT §4's fifth line is
`psql "$DATABASE_URL"` with no password, verified against a real PostgreSQL that refuses a
wrong one — and it holds for `retrieve`, a static password.

**Decision.** The strict label is decided by interception and grant presence:

| Intercepted | Grant | Label |
|---|---|---|
| yes (`https` L1/L2, `postgres` L3) | present | `strict` |
| yes | absent | `strict-unknown` |
| no layer carries the protocol | any | `not-strict` |

**The last row is reached by enumerating the intercepted protocols, never by negating one.**
`ResourceBinding::protocol` is a free-form `String` and `is_postgres()` was its only
discriminator, so `if is_postgres() { .. } else { strict }` would label `redis`, or a typo,
as strict — the overclaim §7 exists to prevent, arrived at by omission. `interception_layer`
had the same shape and reported `L1` by fallthrough; both are corrected.

**The same shape was in the data plane, and running the binary is what found it.**
`AgentHandler::from_grants` gave an HTTPS handler to everything that was not postgres, so a
`redis` binding was **proxied and had its credential injected** while the report said no
layer carried it. Verified live before the fix: a fully-granted `redis` resource returned
200 with the credential accepted upstream, against a row printing `not-strict`.

That direction *underclaims* rather than overclaims, so nothing was unsafe — but the label
and the code disagreed, which is the condition this repository is repeatedly burned by. The
code moved to match the label, per AGENTS.md rule 3: a protocol no layer carries gets no
handler, so the host is as unknown to the proxy as one nobody configured. Confirmed against
the binary: `cache.internal` and a never-configured host now behave identically.

**A label is a claim about the code, so the code is what must be checked.** The reporting
tests all passed while the data plane did the opposite of what they reported, because every
one of them asserted the printed line. `fail_closed.rs::a_protocol_no_layer_carries_is_
denied_rather_than_proxied` closes it, and its fixture is fully authorized — signed grant,
matching subject, credential on disk — so the only thing that can deny is the protocol not
being carried.

Materialization stays orthogonal. It decides *what* credential is presented, not *who holds
it*. `exchange` remains better for reasons §7's strict definition does not measure: a
short-lived, narrowly-scoped credential limits the damage if the **agent** is compromised,
and it is revocable upstream.

**Consequence.** v1's recorded qualification — strict mode not met on the HTTPS path — is
resolved by reporting a property the code already had, not by building a mechanism. The claim
is bounded to an intercepted path, a bound SECURITY §3 already documents; no new limit is
added. `strict-unknown` is unchanged: absence of evidence is not evidence.

Two gaps were found while deciding this and are deliberately **not** fixed here, because
under this rule neither blocks strict mode: `main.rs` wires `UnconfiguredExchange`, so
`exchange` is unreachable in the shipped binary, and the dashboard hardcodes
`Materialization::default()` with no form field. `TokenEndpointExchange` remains dead code
with an invented wire format; deleting or specifying it is a separate decision.

**Consequence of the data-plane half:** a binding on an unintercepted protocol now fails
instead of being silently proxied. A user relying on a typo'd protocol still reaching its
host loses that, which is correct — it was an accident of the `else` branch, and the report
already said no layer carried it.

**Reversed by:** an interception layer that hands the workload the upstream credential
rather than presenting it — at which point the label would again have to ask what was
materialized. Adding a protocol to the enumeration without a layer that carries it would
have the same effect and is the failure mode to watch: **the enumeration now lives in three
places** — `interception_layer`, `strict_label_of`, and `AgentHandler::from_grants` — and a
protocol added to one and not the others reopens exactly this gap.

---

## ADR-0021 — Project scope is optional on both sides, and absent scope is not a wildcard

**2026-09-17 · Accepted**

ROADMAP v1 scopes "Organizations, projects, resources, policy". Step 21 delivered
organizations and deliberately left `projects` as a table no code referenced, on the
reasoning that organization carries the tenant-isolation property and a second scoping key
would be scope by accumulation. That reasoning was right about the *security* boundary and
wrong about the *phase* scope, so project scoping landed as step 21b.

The design question is what a **missing** project means, and it has two different answers
depending on which side is missing.

**Decision.** A resource with no project is organization-wide and reachable from anywhere
in its tenant. A device with no project reaches **only** unprojected resources.

```
resource=None, caller=None        → allow   (every pre-project policy)
resource=None, caller=Some(p)     → allow   (org-wide resource, seen from inside a project)
resource=Some(r), caller=None     → DENY    (absent scope is not a wildcard)
resource=Some(r), caller=Some(c)  → r == c
```

The asymmetry is the whole decision. Making both directions permissive would mean
enrolling a device without a project is the way to reach everything — a fail-open default
reachable by omission, which is the shape AGENTS.md rule 3 forbids. Making both strict
would deny every policy document written before this ADR, turning an additive change into a
breaking one.

`project_id` is therefore NULLABLE in the schema while `organization_id` is NOT NULL: a
record that cannot be placed in a tenant is a bug, but a resource belonging to a whole
organization is a legitimate and common state.

**Consequence.** The project, like the organization, is read from the device's enrolment
row and fixed by the same single `UPDATE ... RETURNING` that consumes the enrolment token.
Nothing a caller sends can widen it. A new scoping key also means every future
tenant-visible read has two filters to get right rather than one, and `cross_project.rs`
exists to catch the ones that only apply the first.

**Reversed by:** projects gaining their own isolation requirements — separate credential
stores, separate audit trails, or a compliance boundary — at which point project stops
being a subdivision of an isolated tenant and becomes a tenant, and the permissive
`resource=None` cell above becomes wrong.

---

## ADR-0020 — Materialization is async; the synchronous client is removed

**2026-09-13 · Accepted** · *Supersedes the decision originally numbered 0012, whose
number was taken on 2026-09-11 by the lint-policy ADR.*

`zs-materializer` fetched credentials with `ureq`, a synchronous HTTP client, from inside
the agent's tokio runtime. Every materialization blocked a runtime worker thread for the
duration of a network round trip to a vault provider.

This is not a throughput preference. The agent's proxy, its L3 postgres listeners, and its
control-plane client all share that runtime. A blocking call in a worker stalls unrelated
connections, and ARCHITECTURE §10's 5 ms added-latency budget is measured across the whole
path — a stall in one resource's materialization shows up as latency on another's request.
Under enough concurrent materializations the runtime starves outright.

**Decision:** materialization is `async`, over `reqwest` (ADR-0013's single outbound
client). `ureq` is removed from the workspace.

**Consequence:** `Protocol` and provider traits on the materialization path are async, so
they need `async_trait` and their implementors become harder to call from synchronous
contexts. Accepted: the synchronous contexts that remain are tests, which run on a runtime
anyway.

**Reversed by:** materialization ceasing to perform I/O — an in-process HSM or a local
agent socket with no network hop. Then the async machinery is pure ceremony and a
synchronous call is the simpler correct answer.

---

## ADR-0019 — Workspace members are production-intent only; prototypes live in spikes outside the workspace

**2026-09-13 · Accepted**

`apps/gateway` sat in the workspace for months. It was v2 surface per ROADMAP, absent from
ARCHITECTURE §2's crate map, and duplicated the agent's credential-injection path with no
TLS on the upstream leg, no grant verification, and a hardcoded identity that its own
authorization check compared against itself. It was listed **twice** in the members array
until step 6 removed the duplicate — a member nobody builds is a member nobody notices is
listed twice.

Membership is a claim. `cargo test --workspace` covering a crate reads as "this is tested
and intended"; `cargo build --workspace` producing a binary reads as "this ships". Neither
was true here, and the gap stayed invisible because nothing forced the question.

**Decision:** a workspace member is production-intent code. Exploratory or superseded code
moves to a spike directory outside the workspace, with a README naming, specifically, why it is not deployable. It
stops being built, tested, linted, and audited by `cargo deny` — which is the point: those
tools asserting a prototype is fine is worse than them saying nothing.

Moving `apps/gateway` out to a spike (step 25) is the precedent. Spikes are not published.

**Consequence:** quarantined code rots. It will not compile against the workspace a few
months later, and that is accepted — a prototype's value is the design question it
answered, not its source. If the code itself is the artefact worth keeping, it belongs in
the workspace with tests, not in a spike.

**Reversed by:** a prototype that needs continuous-integration coverage to stay meaningful
— a compatibility shim tracking an external API, for instance. That is an argument for
making it a real member with real tests, not for relaxing this rule.

---

## ADR-0018 — Revocation is a refresh-time list keyed by grant id, not a per-request check

**2026-09-13 · Accepted**

ROADMAP v1 requires revocation, and SECURITY §4 bounds revocation lag — which presumes a
mechanism to withdraw a **specific** grant exists. Expiry is not that mechanism: shortening
TTLs makes every grant shorter-lived but cannot single one out, and it raises control-plane
load for every workload in order to address one.

Three options were available. A **per-request check** gives zero lag but puts the control
plane in the path of every data-plane request, contradicts ADR-0004's offline verification,
adds a network round trip to the ARCHITECTURE §10 latency budget, and turns a control-plane
outage into a total outage. **Shorter TTLs alone** are not revocation, as above, and would
weaken a claim PRODUCT §7 owns. A **refresh-time list** costs bounded lag and nothing else.

**Decision:** the control plane records withdrawals in `revoked_grants`, keyed by
`grant_id`. `POST /wire/revoke` writes one; `GET /wire/revocations` returns the calling
organization's list. The agent fetches that list on its normal refresh and checks it
locally before every authorization. Revocation lag is bounded by the **refresh interval**,
not by grant TTL.

**Keyed by `grant_id`, not by the authorization tuple.** The control plane withdraws one
decision. Re-minting the same subject/workload/resource is a *new* decision with a new id
and is deliberately not covered — otherwise revoking once would permanently blacklist a
tuple, and an operator could never restore access without a separate un-revoke path.

**The agent's set is additive and never replaced.** The control plane's list is bounded —
it can drop an entry once the revoked grant passes its own expiry — so treating a shorter
list as "these are reinstated" would resurrect exactly the grants that were revoked. An
empty response means "no new revocations", never "clear the set".

**Consequence:** an agent that cannot reach the control plane does not learn of new
revocations. It keeps using cached grants until they expire, which is SECURITY §7 row 5's
stated behaviour; the worst case for an unreachable agent is therefore one TTL, and for a
reachable one, one refresh interval. Both are documented in SECURITY §3 rather than implied.

**Reversed by:** a requirement for zero-lag revocation — a regulated deployment that must
prove access ended at an instant rather than within a window. That would force the
per-request check and, with it, the loss of offline verification. It is a different product
posture, not a tuning change.

---

## ADR-0017 — The agent's grant cache is in memory only, and there is no local-policy fallback

**2026-09-11 · Accepted**

The agent must authorize every request. Two questions follow: where cached grants live,
and what happens when the control plane is unreachable.

**Decision, part one:** the grant cache is **in memory only**. It is keyed by subject +
workload + resource, and expiry is the grant's own `expires_at_ms` — there is no
independent TTL and no eviction timer, because `AgentVerifier::verify` checks expiry on
every lookup, so a stale entry denies rather than lingering as authority. Nothing is
written to disk.

A cache that survives restart would extend revocation lag past the TTL the whole security
model is built on. SECURITY §3 already concedes that revocation takes effect at the next
grant refresh, up to one TTL later, and calls that a deliberate trade. Persisting the
cache turns a bounded window into an unbounded one: a revoked grant would keep working
across restarts until its own expiry, with no refresh to check against.

**Decision, part two:** there is **no fallback to local policy**. The original plan had an
`--offline` flag that read a local policy file when the control plane was unreachable;
that is removed. SECURITY §7 permits "control unreachable, cache valid → allow within
cached grants" and requires "control unreachable, cache expired → deny". Reading a local
file in the second case is a fail-open path a developer can trigger by blocking a port,
and global constraint 3 forbids falling back to a weaker authorization source.

The agent's local config file therefore carries **no authority**: resource-to-host
bindings and pinned verifying keys only. Someone who edits it can misdirect or break their
own agent, but cannot authorize themselves — authority requires a signature they cannot
produce. The credential reference the agent materializes comes from the verified grant,
never from that file, for the same reason.

**Consequence:** a restarted agent has an empty cache and must reach the control plane
before it can authorize anything. That is the cost of bounding revocation lag, and it is
paid at startup rather than during a request. An agent that cannot reach the control
plane and holds no valid cached grant denies — correctly, and visibly, rather than
silently degrading.

**Reversed by:** a disconnected-operation requirement that a support engineer cannot work
around, where the fleet genuinely must authorize for hours without reaching the control
plane. That would need a persisted cache *and* a revocation mechanism that does not depend
on refresh — a CRL the agent can be handed out of band — not simply writing this cache to
disk.

---

## ADR-0016 — The grant-verifying key is delivered at enrolment and pinned by key id

**2026-09-11 · Accepted**

The agent verifies grants offline, which is the whole point of signing them: the data
plane must not have to ask the control plane whether each request is allowed. That only
means something if the agent's trust anchor is established out of band from the grants it
checks. Three options were on the table — pinned in agent config at install time,
delivered during enrolment, or fetched from a `/wire/jwks` endpoint.

**Decision:** the control plane returns its grant-verifying key **and that key's id** in
the enrolment response, over the same exchange that issues the client certificate. The
agent pins it for the life of the enrolment. There is no per-request key fetch and no
`/wire/jwks`.

Rotation is by key id, not by replacement. `SignedGrant::signing_key_id` names the key a
grant was signed with, and `AgentVerifier` holds a set. A new key is pinned alongside the
old one before the control plane starts signing with it, so both verify during the
overlap; the old entry is dropped after it stops being used.

**Why not the alternatives.** A `/wire/jwks` fetch is the tempting one and it is wrong:
an agent that retrieves the verifying key from the same party that signed the grant, at
the moment it verifies, has not verified anything — it has asked the signer to confirm
its own signature. Install-time config pinning is sound but makes rotation an operational
task on every device, and provides no binding between the key and the device's identity.
Enrolment already establishes that binding under mTLS.

**Consequence:** a device cannot be handed a new signing key without re-enrolling or an
explicit rotation that adds the id first. That is deliberate friction — it is what stops
a compromised control plane from silently swapping the key a device trusts. Tested: after
enrolment, rotating the control plane's signing key causes `request_grant` to reject the
grant rather than return it, because the new key id is not pinned.

**Reversed by:** a need to rotate faster than re-enrolment allows across a fleet large
enough that per-device rotation is impractical. That argues for a signed key-set endpoint
whose *own* trust anchor is pinned at enrolment — which is this decision with one more
level of indirection, not a repudiation of it.

---

## ADR-0015 — mTLS enrolment bootstraps from a one-time token

**2026-09-11 · Accepted**

ROADMAP v1 and ARCHITECTURE §1 both specify mTLS for the control↔agent channel. Until
now every `/wire/*` route was unauthenticated: anyone who could reach the port could
enrol a device or inject audit records. Requiring a client certificate creates a
chicken-and-egg problem — the device needs a certificate to talk to the control plane,
and the control plane is what issues it.

**Decision:** enrolment bootstraps from a one-time token, and the control plane issues
the client certificate.

1. An operator creates an enrolment token, scoped to one organization, single-use, short
   TTL (15 minutes).
2. The device generates its keypair **locally**. The private key never leaves the machine.
3. The device calls `POST /wire/enroll` over one-way TLS with the token, its public key,
   and a CSR.
4. The control plane validates and consumes the token, issues a client certificate whose
   subject binds `device_id` and `organization`, and returns it along with the
   grant-verifying key (ADR-0016).
5. Every subsequent `/wire/*` call requires that client certificate.

`/wire/enroll` is the only route reachable without a client certificate.

**Consequence:** an operator action is required before a device can enrol, which is
friction by design — it is the human step that makes device identity mean something.
Token distribution becomes a thing that can be done badly; the single-use short TTL
bounds the damage. The certificate's binding of `device_id` means a valid certificate for
device A cannot request grants as device B.

**Reversed by:** a platform attestation mechanism strong enough to replace the operator
step — TPM-backed or cloud instance identity. That would remove the token, not the mTLS.

---

## ADR-0014 — Custom request signing is deferred to v2

**2026-09-11 · Accepted**

ROADMAP v1's data plane lists "HTTPS: bearer, basic, api-key header, query parameter,
custom signing". The first four are mechanical header or query manipulations. Custom
signing — AWS SigV4 and similar — is different in kind: the signature covers the request
body and a canonical form of the headers, so the proxy must reconstruct a
provider-specific canonicalization and re-sign after injection.

**Decision:** v1 ships bearer, basic, api-key header, and query parameter. Custom signing
is v2.

**Consequence:** ZeroSecret cannot front an AWS API in v1. That is a real gap and must be
stated when the data plane is described, not discovered by a design partner. The four
shipped schemes cover the API-key-shaped majority, which is what PRODUCT §4's demo needs.

**Reversed by:** a design partner whose primary resource requires SigV4. The work is
bounded but it pulls in per-provider canonicalization, which is the shape ROADMAP's
"Deliberately unscheduled" plugin system exists to avoid.

---

## ADR-0013 — One outbound HTTP client

**2026-09-11 · Accepted**

The workspace had accumulated four ways to make an HTTP request: `reqwest` (declared,
unused), `ureq` (`zs-materializer`, `apps/control`), a hand-written serializer over a raw
`TcpStream` (`apps/gateway`), and `zs-mitm`'s own request serializer. Four request
builders and four TLS configurations, each a place a certificate-verification default can
be wrong.

**Decision:** `reqwest` with `rustls` is the single client for outbound calls to a service
— credential providers, OIDC, the control plane. `ureq` is removed.

**Consequence:** one TLS configuration to audit for client calls.

**Reversed by:** nothing for the client half. The proxy exemption: ADR-0039.

---

## ADR-0012 — Lint policy lives in the repository, not in a CI argument

**2026-09-11 · Accepted**

Clippy was invoked as `cargo clippy --all-targets -- -D warnings` in CI and nowhere else.
The tree was clean under it, but the policy was invisible to a local `cargo clippy`,
unreviewable in a diff, and silently dependent on whatever `stable` resolved to that day.
Default clippy also does not flag `unwrap()`: `apps/control` had 26 `unwrap`/`expect`/
`panic` sites with no test module, 20 of them `lock().unwrap()`. A poisoned mutex there
panics a request handler rather than denying it, contradicting the fail-closed rule.

**Decision:** `[workspace.lints.clippy]` in `Cargo.toml` with `lints.workspace = true` on
every member; `rust-toolchain.toml` pins the toolchain. `unwrap_used`, `expect_used`, and
`panic` start at `warn` and are promoted to `deny` per crate as each is cleaned.

`-D warnings` cannot express "deny what is clean, phase in what is not" — it promotes the
new lints to errors too. So CI passes `-A` for exactly the three lints being phased in.
Any incrementally adopted lint needs that treatment, or a per-crate `deny` instead.

**Consequence:** a clippy upgrade is now a deliberate one-line change with its own CI run.
The three `-A` flags are a standing reminder of unfinished work; they shrink as crates are
cleaned and the entry is superseded when the last one goes.

**Reversed by:** finishing the cleanup, at which point the `-A` flags are deleted and the
lints move to `deny` workspace-wide.

---

## ADR-0011 — The control↔agent wire is JSON over HTTPS, not gRPC

**2026-09-11 · Accepted · amends ARCHITECTURE §2**

ARCHITECTURE §2 specified `zs-wire` as "control <-> agent gRPC types" and `apps/control`
as "axum, tonic, sqlx". The implementation was plain serde structs over HTTP, with no
tonic anywhere. One of the two had to move.

**Decision:** JSON over HTTPS. `zs-wire` stays serde DTOs. Tonic is removed from the
architecture.

The traffic is enrolment, grant mint, policy pull, and audit push — low-frequency
request/response with no streaming and no bidirectional calls. gRPC's real benefit here
would be a single canonical schema, and ADR-0001 already provides that by compiling the
same Rust types into both sides. What remains is cost: a proto toolchain, a second schema
language, and worse debuggability at precisely the boundary most needed during an
incident.

**Consequence:** no `.proto` files, no codegen step. If server-push is needed for
revocation, SSE from the control plane's `chi` server (ADR-0049, ADR-0051) is a smaller step
than adopting tonic.
`zs-wire` DTOs stay deliberately stringly-typed rather than depending on `zs-identity`,
so a change to `Subject`'s internals cannot break the wire format of deployed agents.

**Reversed by:** a requirement for bidirectional streaming, or a polyglot client that
makes a language-neutral IDL worth its cost.

---

## ADR-0010 — Execution state lives in files, not in tool sessions

**2026-09-05 · Accepted**

This repository is worked by several models across several tools — Claude Code, Codex,
Gemini CLI, Cursor. Each keeps its own session store and none of them can read another's.
A run killed mid-task cannot be resumed by a different tool, and often not by a different
session of the same tool.

**Decision:** the repository carries its own execution state. A state file holds
position and next action. A journal is an append-only history. Plans carry
per-step status and evidence. An agent instruction file defines the read-then-one-step-then-write
protocol, and every tool-specific instruction file is a thin pointer to it. These files stay in
the private upstream and are not published.

**Consequence:** every session pays a small read-and-write tax. In exchange, no work is
lost to a killed session, and the model doing the next step does not have to be the model
that did the last one.

**Reversed by:** nothing. A single-tool, single-model workflow would make it optional,
not wrong.

---

## ADR-0009 — Server-rendered dashboard in Rust, no separate frontend application

**2026-09-05 · Accepted · amends ADR-0001**

The first draft of ARCHITECTURE.md carried React and TypeScript in a `web/` directory.
That contradicted the justification for ADR-0001: a TypeScript frontend re-declares
`Resource`, `Policy`, `Grant`, and `AuditRecord` in a second language, which is the
representation drift ADR-0001 exists to eliminate.

**Decision:** the dashboard is server-rendered inside `apps/control` using `maud`
templates, htmx, and Tailwind through its standalone CLI. No npm, no bundler, no
`web/` deploy target. `askama` is an acceptable substitute for `maud`.

**Rationale:**

- The v1 dashboard is CRUD — resources, policies, members, audit. htmx covers it.
- One type declaration. Handlers render from the same structs the policy engine uses.
- No npm dependency tree. For a product whose install a security engineer must approve,
  several hundred transitive JavaScript packages in the console is a real audit cost.
- One fewer deploy target and one fewer CI lane.

**Rejected: Leptos or Dioxus.** Rust end to end and genuinely capable, but they
reintroduce a WASM build pipeline, ship a large bundle, and buy client-side reactivity a
CRUD console does not need.

**Consequence:** the visual request composer — drag rules, live preview of the mutated
request — is weak in htmx. It moves to v2 and arrives as one JavaScript island mounted
inside a server-rendered page, never as a second application.

**Reversed by:** the console becoming genuinely interactive across most of its surface,
not one screen. Reversing means a frontend specialist and a shared type-generation step
from the Rust structs; it does not mean hand-maintained TypeScript models.

---

## ADR-0008 — Five owner documents, hard cap

**2026-09-05 · Accepted**

The previous repository accumulated 153k lines of documentation, nearly matching its
code volume, with decisions restated across files and superseded documents retained "for
historical reference".

**Decision:** exactly five owner documents — PRODUCT, ARCHITECTURE, SECURITY, ROADMAP,
DECISIONS. One decision has one owner. Other files link to the owner and never restate
it. Superseded content is deleted, not marked historical.

**Consequence:** a sixth owner file means a scope problem, not a documentation problem.

**Reversed by:** the repository holding genuinely independent subsystems with separate
audiences.

---

## ADR-0007 — One product in this repository

**2026-09-05 · Accepted**

**Decision:** ZeroSecret only. The webhook delivery product does not live here and does
not share a roadmap.

**Consequence:** no shared platform layer built speculatively for a second product. The
previous repository's shared identity foundation existed mainly to serve two products
and cost more than it saved.

**Reversed by:** a second product that genuinely needs the same data plane, after the
first one has customers.

---

## ADR-0006 — Do not build a vault

**2026-09-05 · Accepted**

Vault, OpenBao, Infisical, AWS Secrets Manager, and 1Password have large integration
ecosystems and years of head start.

**Decision:** ZeroSecret is the credential consumption layer. It integrates with existing
custody products and never competes with them on storage, rotation, or scanning.

**Consequence:** the sale becomes "make your existing secret manager safer for
development" rather than "replace Vault". Materially easier.

**Reversed by:** nothing foreseeable. This is the commercial spine.

---

## ADR-0005 — Layered interception, chosen per resource

**2026-09-05 · Accepted**

Transparent interception is the strongest guarantee and the worst support burden:
certificate pinning, custom trust stores, containers, VPNs, and EDR all fight it.

**Decision:** four layers — explicit proxy, process-scoped, protocol listener,
transparent TUN. Always use the least invasive layer that satisfies the invariant.
Choice is per resource and visible to the user. TUN is deferred.

**Consequence:** ZeroSecret cannot claim it intercepts everything, and will not.

**Reversed by:** nothing. The layering is the honest position.

---

## ADR-0004 — Signed grants verified offline

**2026-09-05 · Accepted**

Calling the control plane on every request adds latency to every developer HTTP call and
makes the control plane a hard availability dependency for local development.

**Decision:** the control plane mints short-lived signed grants after policy evaluation.
The agent verifies them offline using the shared `zs-grant` crate.

**Consequence:** revocation lag bounded by grant TTL. Documented in
[SECURITY.md](SECURITY.md), never hidden. Refresh performs a revocation check.

**Reversed by:** a customer requirement for sub-second revocation, which would force a
synchronous mode for specific resources.

---

## ADR-0003 — OIDC relying party only

**2026-09-05 · Accepted**

The previous repository self-hosted an identity provider. Operating, patching, and being
on call for an IdP is a product in itself.

**Decision:** ZeroSecret is a pure OIDC relying party. It federates to the customer's
existing IdP — Okta, Entra, Google, Auth0. No user directory, no password storage, no
MFA implementation, no SCIM in v1.

**Consequence:** individual developers without an IdP cannot use the hosted control
plane in v1. Accepted: individuals are not the buyer.

**Reversed by:** a free tier that must work without any IdP, which would need one
additional narrowly-scoped auth path.

---

## ADR-0002 — Control plane owns configuration

**2026-09-05 · Accepted**

**Decision:** the control plane is the single source of truth for resources and policy.
No committed `zerosecret.yaml`. The agent keeps a read-only cache bounded by grant TTL,
then fails closed.

**Consequence:** no self-managed configuration mode in v1. A prospect who refuses to send
resource configuration to the ZeroSecret cloud cannot pilot v1. That is a known,
accepted loss; the alternative doubles the configuration surface and the test matrix and
creates drift between dashboard and enforcement.

**Reversed by:** a design-partner blocker on data residency, which would be answered by
private control-plane deployment rather than by a second config path.

---

## ADR-0001 — Rust across the data plane and the control plane

**2026-09-05 · Accepted**

The alternative was Go for the control plane and Rust for the agent, which is faster to
build and the conventional split.

**Decision:** Rust for agent, control plane, and gateway. React and TypeScript for the
dashboard.

**The justification is exactly one thing:** `zs-policy` and `zs-grant` compile into both
the control plane and the agent. One canonical policy evaluator, one canonical grant
serialization, no representation drift on the path that decides whether a credential is
released.

**Consequence:** slower delivery on integration-heavy control-plane work — provider
adapters, OAuth flows, CRUD, background jobs — where Go is markedly less ceremonious.
Accepted because most of this control plane is a security primitive, not CRUD.

**Reversed by:** the shared crates ceasing to be shared. If policy evaluation ends up
living only in the control plane, this decision loses its entire justification and Go
becomes the better answer.
