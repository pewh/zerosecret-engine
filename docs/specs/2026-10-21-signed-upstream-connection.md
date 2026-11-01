# The signed grant names the upstream connection

**2026-10-21 · Approved by the owner 2026-10-21** · parent spec `docs/specs/2026-10-16-plain-zs-run.md` ·
follows ADR-0037 · closes the limit "A committed binding still chooses how the agent reaches a
granted host" (SECURITY §3)

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

## 1. Intent

App repositories commit `zs-policy.json` (ADR-0036). Since ADR-0037 the signed grant names the
resource's `host` and `protocol`, so a pull request cannot point a binding at another host name.
It can still change how the agent reaches that host:

| File field | What a committed change does today |
|---|---|
| `upstream_host` (`--enrollment-token` path only; refused with a stored enrolment) | sends an https binding's credential to another server |
| `upstream_port` | sends the credential to another port of the granted host. For https and http with no override, the workload's CONNECT already picks the port (`classify`, `apps/zs/src/lib.rs:997`) |
| `upstream_plaintext` | turns upstream TLS off (mongo on any host; https to a loopback upstream) |
| `upstream_ca` | adds a trusted CA on a mysql, postgres or mongo binding |
| `upstream_cert_sha256` | pins a leaf and skips name, chain and date checks |
| removing `upstream_ca`/`upstream_cert_sha256` | brings back the postgres/mysql plaintext fallback |
| `local_endpoint` | opens a loopback endpoint; on aws-sigv4 also `POST /.zs/presign`, whose URLs outlive the grant |

The owner treats all of these as equally serious (2026-10-21: "a new port, TLS turned off, a
different CA or pin"). After this change, an admin sets these values per resource in the
dashboard, and the control plane signs them into the grant. A value that is changed only in the
file stops `zs run` before the child starts, the same way a changed host does today. The stop
message tells the developer exactly what differs and what to do.

## 2. Goals, non-goals, anti-goals

**Goals**

1. With a control plane (stored enrolment or `--enrollment-token`), the agent reaches a granted
   resource only through the upstream host, port, TLS mode and CA/pin that the control plane
   signed, and opens a local endpoint only when it is signed.
2. An admin sets and changes these values in the dashboard (owner, 2026-10-21). The only other
   path is the operator's seed file on the control host (`ZS_CONTROL_POLICY`, 4.3), which is
   validated the same way. An app repository has no path to them.
3. Developer experience stays good (owner, 2026-10-21):
   - a file may leave these fields out and take the signed values, so most files get shorter;
   - every stop message names the resource, the field, the file value and the signed value,
     and says what to do;
   - the CA bundle stays a file in the repo; only its SHA-256 goes to the dashboard, and
     `zs ca-sha256 <file>` prints it (C9).

**Non-goals**

- `auth` (the injection scheme and its header, param or field). It stays an accepted limit
  (owner, 2026-10-20). Section 4.10 records why, and nothing in this design blocks signing it
  later as one more field.
- Local mode (no control URL). It trusts the file's own keys by design (ADR-0037) and gets no
  new protection.
- Approval workflows, history UI or diffs for policy changes.
- Who may write to the dashboard (O6). Today any identity the IdP verifies gets a dashboard
  session (`apps/control/src/session.rs:365-371`), and every write checks only the session and
  the CSRF token (`authorize_form`, `:615-639`); member roles are stored but not enforced. So
  in this spec "admin" means anyone who can write to the dashboard. This spec moves a
  connection change out of the app repository into a logged dashboard edit; enforcing an admin
  role on every dashboard write is the next spec.
- Changing a running agent's connection when the admin edits the resource. A restart applies it
  (4.6).

**Anti-goals** (failure even if it technically works)

- Any path where a value from the file, not from the signature, decides the upstream host,
  port, TLS mode, trust anchor or local endpoint while a control plane is configured.
- A silent fallback: a mismatch that starts the child, or that downgrades instead of stopping.
- Pasting a 170 KB CA bundle into the dashboard, or sending it in every grant. Acme's
  `zerosecret/config/rds-global-bundle.pem` is 169,984 bytes and holds 111 certificates.
- A stop message that prints a secret. Hosts, ports, TLS modes and SHA-256 values are not
  secrets.

## 3. Decisions

**Owner decisions**

| # | Decision | Date |
|---|---|---|
| O1 | Sign `upstream_port`, `upstream_plaintext`, `upstream_ca`, `upstream_cert_sha256`, `local_endpoint`; `auth` stays an accepted limit | 2026-10-20 |
| O2 | All four changes (port, TLS off, CA, pin) matter equally | 2026-10-21 |
| O3 | An admin sets the values in the dashboard | 2026-10-21 |
| O4 | The CA is identified by the SHA-256 of the file's bytes; the file stays in the repo | 2026-10-21 |
| O5 | Keep a good developer experience without weakening security | 2026-10-21 |
| O6 | Dashboard write roles are a separate spec, next; this spec does not gate dashboard writes. Gating only the connection fields would add nothing while any member can edit grants | 2026-10-21 |

**My calls** (the owner can veto any of them in review; the cost if wrong is next to each)

| # | Call | Cost if wrong |
|---|---|---|
| C1 | `upstream_host` is signed too. It is the largest gap on the token path, where the acme and globex harnesses use it. A stored enrolment then accepts `upstream_host` when it equals the signed value, instead of refusing it | Harness control rows gain columns (4.9). Without C1, the token path keeps the worst gap |
| C2 | For https and http with no signed port, the signed port is the protocol default (443, 80). A CONNECT to another port of a granted host is denied (4.5). Every binding in acme, globex and initech uses the default port or sets one | A workload that reaches a granted host on an unusual port needs the admin to sign that port |
| C3 | The control plane signs resolved values: `upstream_host` and `upstream_port` are always concrete, with no "empty means default" | None found; it removes a class of ambiguity from the check |
| C4 | One signed field `upstream_tls` holds the TLS mode: `default`, `plaintext`, `ca-sha256:<hex>` or `pin-sha256:<hex>` (4.1) | The four file fields stay as they are; only the signed side is merged |
| C5 | A file field that is left out takes the signed value. A file field that is set must equal it | A reviewer cannot see the connection in the file alone; `zs resources` shows the signed values (4.7) |
| C6 | The connection is fixed at startup. A renewed grant with a different connection is skipped with a "restart" line (as ADR-0037 does for host) | An admin change needs a restart. Until then the old grant runs out (within 5 minutes) and requests are denied with the restart line |
| C7 | The connection rules live in one function in `zs-policy`, used by the dashboard, by `wire_grant` and by the agent | None |
| C8 | Policy edits that change a connection field print `control: resource connection changed by <subject>` with the resource name, like the existing `operator.note` lines | None |
| C9 | The CA SHA-256 is taken over the certificates in the file, not the raw bytes: SHA-256 of the DER certificates concatenated in file order (DER is self-delimiting). Line endings (a Windows checkout with `core.autocrlf`, acme has no `.gitattributes`), comments and whitespace do not change it; any change to the trusted set does. `zs ca-sha256 <file>` prints it, and the generators and the dashboard help text use it | `shasum -a 256` no longer gives the value; the stop message and `zs ca-sha256` do |
| C10 | The seed file (`ZS_CONTROL_POLICY`, `apps/control/src/main.rs:25-41`) may carry `connection` blocks. `control` validates each with C7 and refuses to start on an invalid one, naming the resource | None; today the seed is not validated at all |

## 4. Design

```mermaid
sequenceDiagram
    participant Admin
    participant Dash as control dashboard
    participant Ctl as control /wire/grant
    participant Zs as zs run
    participant File as zs-policy.json + CA file
    Admin->>Dash: set upstream host, port, TLS, CA SHA-256, local endpoint
    Dash->>Dash: validate (zs-policy rules), store in policy document
    Zs->>File: load bindings
    Zs->>Ctl: mint grant (device, subject, workload, resource, ops)
    Ctl->>Zs: signed grant with host, protocol and the connection
    Zs->>File: read the CA file once, hash it
    Zs->>Zs: effective connection = signed values; file values must match
    alt any field differs
        Zs-->>Admin: stop before the child, print the field, file value, signed value
    else all match
        Zs->>Zs: open listeners and local endpoint from the effective connection
        Zs->>Zs: start the child
    end
```

### 4.1 The connection fields

`zs_policy::ResourcePolicy` gains one optional block, stored in the existing
`policies.document` JSONB (no SQL migration; old documents read with defaults):

```json
{
  "name": "acme-mysql",
  "host": "acme-db.cluster-example.ap-southeast-3.rds.amazonaws.com",
  "protocol": "mysql",
  "operations": ["connect"],
  "connection": {
    "upstream_host": null,
    "upstream_port": null,
    "upstream_tls": "ca-sha256:<64 lowercase hex>",
    "local_endpoint": false
  }
}
```

| Field | Values | Default when absent |
|---|---|---|
| `upstream_host` | host name or IP literal | the resource `host` |
| `upstream_port` | 1-65535 | protocol default: https 443, http 80, postgres 5432, mysql 3306, mongo 27017 |
| `upstream_tls` | `default`, `plaintext`, `ca-sha256:<hex>`, `pin-sha256:<hex>` | `default` |
| `local_endpoint` | bool | `false` |

`default` means what a binding without TLS fields does today: https verifies against the system
roots and the host name; http is always plaintext; postgres and mysql use system roots with
their current plaintext fallback; mongo uses system roots.

**Rules** (one function, `zs_policy::Connection::validate(protocol)`, C7). These are today's
agent load rules (`apps/zs/src/lib.rs:113-142`, `267-330`, `607-615`), moved:

- `ca-sha256` and `pin-sha256`: postgres, mysql and mongo only; 64 hex digits, stored lowercase.
- `plaintext`: mongo on any host; https only when the upstream host is loopback (`localhost`,
  or a loopback IP literal); refused on postgres, mysql and http (http is always plaintext).
- `local_endpoint: true`: https only.
- A protocol the agent does not intercept accepts only the defaults.

### 4.2 The grant

`zs_grant::Grant` gains four fields with no serde default, like `host` (ADR-0037):

```rust
pub upstream_host: String,      // resolved, never empty (C3)
pub upstream_port: u16,         // resolved (C3)
pub upstream_tls: UpstreamTlsMode, // Default | Plaintext | CaSha256([u8; 32]) | PinSha256([u8; 32])
pub local_endpoint: bool,
```

The canonical payload keeps alphabetical key order, so the new keys go in as
`local_endpoint` (between `host` and `materialization`) and `upstream_host`, `upstream_port`,
`upstream_tls` (between `subject` and `workload`). Values: `true`/`false`; the host as is; the
port in decimal; the TLS mode as its string form from 4.1.

`wire_grant` (`apps/control/src/wire.rs:333`) fills them from `evaluation.resource`, resolving
defaults. It validates the connection first. An invalid stored connection (for example a
document edited by hand) is refused like an unknown resource, and nothing is signed.
`GrantMintRequest` is unchanged: the agent still never sends its binding to the control plane.

### 4.3 The dashboard

- The create form (`apps/control/src/dashboard.rs:203-212`) and the inline edit row (`:138-158`)
  gain: upstream host, upstream port, TLS mode (select: default, plaintext, CA bundle, pinned
  leaf), SHA-256 (for CA bundle or pinned leaf), local endpoint (checkbox). Empty means default.
- Help text next to the SHA-256 field: `zs ca-sha256 <file>` for a CA bundle (C9),
  `openssl x509 -outform der -in <cert> | shasum -a 256` for a pinned leaf. The agent's stop
  message also prints the hash of the CA file it read (4.6).
- `create_resource` (`:550-596`) and `update_resource` (`:637-729`) parse and validate the block
  with C7 and answer 400 with the rule's message on failure. `update_resource` carries the block
  across when the edit row does not send it; the literal at `:713-721` must not drop it.
- The resources table shows a short connection summary per row (for example
  `127.0.0.1:59080 plaintext`, `ca e3b0c442…`). It shows only what differs from the default.
- C8: a change to the block prints `control: resource connection changed by <subject>` with
  the resource name. Versions already stay as rows in `policies`.
- C10: the seed file goes through the same validation at startup.

### 4.4 The agent: effective connection

At startup, after `enrol_and_fetch` (`apps/zs/src/run.rs:705`) and before any listener
(`:822` onward) or the child (`:1121`), the agent computes each binding's **effective
connection**:

1. If the startup grant for the binding exists, the effective connection is the grant's
   connection. Each file field that is set must equal it (C5):

   | File | Signed | Equal when |
   |---|---|---|
   | `upstream_host` | `upstream_host` | ASCII case-insensitive |
   | `upstream_port` | `upstream_port` | equal |
   | `upstream_plaintext: true` | `upstream_tls` | is `plaintext` |
   | `upstream_ca: <path>` | `upstream_tls` | is `ca-sha256:H` and the file's certificate hash (C9) is H |
   | `upstream_cert_sha256: <hex>` | `upstream_tls` | is `pin-sha256:` the same 32 bytes |
   | `local_endpoint: true` | `local_endpoint` | is `true` |

   A file `upstream_plaintext: false` or `local_endpoint: false` is the serde default and is
   treated as "not set". So a file cannot ask for TLS when the admin signed `plaintext`, or
   turn off a signed endpoint. Neither gives the file more reach than the signature does.
2. If the signed mode is `ca-sha256:H`, the file must name the CA with `upstream_ca`. Without it
   the run stops (4.6). The CA file is read **once**; the agent parses that buffer, hashes the
   parsed certificates (C9), and builds the trust store from the same certificates. Today it is read twice (`zs_upstream::tls::load_roots`, called at config
   validation and again at listener setup). The builder removes the second read so the hashed
   bytes are the parsed bytes.
3. If a binding has no startup grant (today: `zs: no grant for <r>: <e>`, the run continues), its
   effective connection comes from the file. Today no later grant can arrive for it: renewal
   skips a binding with no grant (`grant_needs_renewal`, `apps/zs/src/lib.rs:882-893`;
   `renew_grants`, `apps/zs/src/run.rs:262-264`), so its requests are denied. Step 4 still checks
   any grant against this effective connection, as a guard, so a later change that mints on a
   miss cannot let a file value carry a credential. No mint-on-miss is added here.
4. `grant_matches_binding` becomes `grant_matches(signed, binding, effective)`, which returns the
   first differing field. It runs where the host check runs today: at startup (stop), at renewal
   (skip, C6), and in `authorized` per request (deny).
5. Listeners, upstream TLS configs (`UpstreamTls` built from the effective mode and the one CA
   buffer), `classify` and the local endpoint all read the effective connection, not the binding.

Effective-connection validation reuses C7. The file's own load checks stay for local mode and
for clear early errors.

### 4.5 https and http: which port the workload may use (C2)

`classify` (`apps/zs/src/lib.rs:980`) intercepts a CONNECT to a granted host when its port is
the effective `upstream_port` or the protocol default, and forwards to the effective
`upstream_host:upstream_port`. Any other port is denied with
`port <n> is not the signed port <m>`. The protocol default stays accepted, because the
harnesses point `https://<granted host>` (port 443) at a signed loopback upstream
(`127.0.0.1:59080`).

Every current binding fits (checked 2026-10-21): acme's https bindings use 443; the acme probes
use 443 with a signed loopback upstream; initech's ten https bindings use 443, and its only http
binding (`initech-plain-http`, `fetch-vendor.ts:7`, `http://203.0.113.10/...`) uses 80. The
`local_endpoint` origin port is fixed at 443 (`crates/zs-mitm/src/proxy.rs:522-560`), which is
the default.

### 4.6 Messages

Every message starts `zs: <resource>:` and goes through `stderr_line!`. Exact text:

| When | Text |
|---|---|
| Startup, a field differs | `zs: <resource>: <field> is <file value> in the policy file, but the control plane signed <signed value>; remove <field> from the policy file, or ask an admin to change resource <resource>` |
| Startup, CA hash differs | `zs: <resource>: upstream_ca <path> has SHA-256 <file hex>, but the control plane signed <signed hex>; restore the file, or, if the new file is intended, ask an admin to set the resource's CA SHA-256 to <file hex>` |
| Startup, CA signed, no path | `zs: <resource>: the control plane signed a CA bundle with SHA-256 <hex>; set upstream_ca to that file` |
| Startup, CA file unreadable | `zs: <resource>: cannot read upstream_ca <path>` (no file content) |
| Renewal, connection changed | `zs: <resource>: the control plane changed <field> (signed <value>, running <value>); restart zs run to use it` |
| Request denied | the existing deny reason plus `<field> differs from the grant`, and for C2 `port <n> is not the signed port <m>` |

The existing `zs: <resource>: binding host does not match the grant` (ADR-0037) stays for `host`
and `protocol`. The stored-enrolment refusal
`zs: <resource>: upstream_host is not allowed with a stored enrolment` is removed (C1): the
field check replaces it.

### 4.7 `zs resources` and `zs ca-sha256`

`zs resources` (`apps/zs/src/main.rs:396-425`) reads only the file today. With a stored
enrolment, it also fetches `GET /wire/policy` (`apps/control/src/wire.rs:118-139`, client
`apps/zs/src/wire_client.rs:184`) and prints each binding's connection as the control plane
holds it (`upstream 127.0.0.1:59080 plaintext`, `ca e3b0c442…`, `local endpoint`), labelled
`control plane (display only)`, so a reviewer can see what a file without upstream fields will
do (C5). This is display only: the policy response is not signed, and only the grant decides.
Grants stay in memory only (ADR-0017); no grant cache is added. Without an enrolment, or if the
fetch fails, it prints `connection: signed at run time`.

`zs ca-sha256 <file>` prints the C9 hash of a CA bundle, or `zs: <file>: not a PEM certificate
bundle`. It needs no control plane.

### 4.8 Paths

| Path | Before | After |
|---|---|---|
| Stored enrolment (`zs login`, plain `zs run`) | host and protocol signed; `upstream_host` refused; other fields free | everything in 4.1 signed and checked |
| `--enrollment-token` | host and protocol signed; all upstream fields free | the same as the stored enrolment |
| Local mode (no control URL) | file keys and grants | unchanged in effect. File grants are `Grant` values, so they now carry the new fields; the same check runs against them; the file signs them itself, so this is no protection (ADR-0037) |

### 4.9 Compatibility and migration

**Releases.** `zs` and `control` ship from the same release (ADR-0036, ADR-0037). A grant from
an older `control` has none of the new fields: it does not parse and the agent refuses it. An
older `zs` cannot verify a new grant (its payload lacks the new keys): it has no grant and fails
closed. No version field is added.

**Stored resources.** An existing resource has no `connection` block, so it signs the defaults.
After the upgrade, a binding that sets a non-default value stops with the message from 4.6 until
an admin sets that value. That is the intended upgrade path and is fail-closed.

**What each real app needs** (values are not secrets):

| App | Resource | Admin sets | File after |
|---|---|---|---|
| acme (committed `zs-policy.json`, zs-dev control) | `acme-mysql`, `acme-mysql-replica` | `upstream_tls = ca-sha256:<hash of rds-global-bundle.pem>` | keeps `upstream_ca` path |
| | `acme-mongo` | `upstream_tls = plaintext` (port 27017 is the default) | may drop `upstream_port` and `upstream_plaintext` |
| | `acme-auth`, `acme-service-a`, `acme-service-b` | nothing | unchanged |
| acme E2E probes | `probe-basic`, `probe-post`, `probe-service-b` | `upstream_host 127.0.0.1`, `upstream_port 59080`, `upstream_tls plaintext` | unchanged or shorter |
| globex E2E and zs-dev | `globex-pg` | `upstream_host` (RDS name found at run time), `upstream_port` (from `.env`), `upstream_tls = ca-sha256:<hash>` | unchanged |
| initech E2E | `initech-pg` | `upstream_port 5432` (default), `upstream_tls = pin-sha256:<hash>` | unchanged |
| | `initech-s3` | `local_endpoint true` | unchanged |

**Harnesses.** All three create resources through `POST /resources/create` from
`control-resources.tsv` (acme `lib/control-setup.sh:34-44` and `lib/dev-stack.sh:165-176`,
globex `lib/control-setup.sh:34-44` and `lib/dev-stack.sh:165` (`dev_configure`, used by
`zs-dev.sh:59`), initech `lib/control-setup.sh` ~38). The TSV gains columns `upstream_host`,
`upstream_port`, `upstream_tls`, `local_endpoint`, written by the generators (acme
`lib/bindings.cjs` `controlResources`; globex `lib/bindings.cjs` `controlRow`, called from
`lib/prepare.cjs` and `lib/dev-prepare.cjs:30`; initech `lib/prepare.ts:215-228`) from the same
values they put in the bindings. The generators get the CA hash from `zs ca-sha256`. Acme and globex are test beds: their changes are staged
there, and their commit state is not a blocker.

### 4.10 What stays local, and why

| Field | Why it can stay in the file |
|---|---|
| `listen_port` | the local listener port on loopback; it never carries the credential off the machine |
| `paths` | narrows where on the signed host the credential is injected; the grant's operations still bound every request |
| `user`, `auth_source` (mongo) | name the account and database for SCRAM to the signed host; SCRAM never sends the password |
| `client_auth_plugin` (mysql) | the plugin between the local client and the agent; the upstream handshake is unchanged |
| `auth` | accepted limit (O1). It decides whether the raw secret or only a signature goes on the wire, and where. It is the same host, port and TLS after this change. SECURITY §3 keeps it as a named limit |

## 5. Docs

- **ADR-0038** "The signed grant names the upstream connection": fields, payload keys, resolved
  values, the effective connection, C2, compatibility, and the ruling that replaces ADR-0037's
  `upstream_host` refusal. ADR-0037 "Not closed here" points to it.
- **SECURITY §3**: rewrite "A committed binding still chooses how the agent reaches a granted
  host" so that it keeps only `auth`, the local-only fields of 4.10 and local mode. Add that a
  connection value is now as strong as dashboard write access, which any signed-in identity
  has until the dashboard-roles spec lands (O6). §7 gains one
  row per check in 4.4-4.6, each with a named `fail_closed_matrix` test. The row for the
  stored-enrolment `upstream_host` refusal is rewritten to the new check.
- **README** and **ARCHITECTURE**: the binding fields table says which fields the control plane
  signs and that a file may leave them out.

## 6. Tests the plan must include

Each test fails before its change and passes after (repo rule).

1. `zs-grant`: changing any new field after signing breaks verification; a grant JSON without the
   new fields does not parse; canonical payload key order is alphabetical.
2. `zs-policy`: every rule in 4.1, accepted and refused, through `Connection::validate`.
3. control: create and update accept, refuse (400 with the rule text) and keep the block;
   `wire_grant` signs resolved defaults and refuses an invalid stored block; an old policy
   document without `connection` loads and signs defaults (with `DATABASE_URL`; show timings,
   because DB tests "pass" in 0.00 s without it).
4. `zs`, stored enrolment **and** `--enrollment-token`: for each row of the table in 4.4, a file
   value that differs stops the run before the child starts, with the exact 4.6 text, and a
   file that leaves the field out takes the signed value (listener, TLS and endpoint behave as
   signed).
5. `zs`: CA file changed after the admin set its hash → stop; the same certificates with CRLF
   line endings or an added comment → same hash (C9); CA file read once; renewal with a changed
   connection skips with the restart line; a per-request grant with a different connection is
   denied; C2 CONNECT to a non-signed port is denied and to the default or signed port is
   allowed; for a binding with no startup grant, a grant inserted into the cache directly with a
   connection that differs from the file-derived one is denied (4.4 step 3, a guard);
   `zs ca-sha256` output; `zs resources` display with and without an enrolment.
   control: a seed file with an invalid `connection` stops `control` at startup (C10).
6. `fail_closed_matrix`: one row per new SECURITY §7 row; the meta-test row count updated.
7. E2E: acme plain `zs run` (stored enrolment), acme, globex and initech harnesses with the new
   TSV columns. **Ask the owner before running any of them or restarting the zs-dev stack.**

## 7. Left to the builder

- Type names and module layout (`Connection`, `UpstreamTlsMode`, where `grant_matches` lives).
- How the dashboard lays out the new fields, as long as 4.3 holds.
- How the ~21 `Grant {` literals in 16 files get the new fields (a test helper is fine). The code
  graph misses struct literals; grep `Grant {`.
- Whether `zs resources` (4.7) reads the cached grant from the existing grant cache or the
  enrolment store.
- The order of plan tasks, as long as each task leaves the workspace gates green.
