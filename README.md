# ZeroSecret

Your code can use credentials it never possesses.

ZeroSecret is a secretless development runtime. The agent, `zs`, runs your workload with no
credential in its environment, files or arguments. It intercepts the workload's outbound
traffic and adds the credential only on the upstream leg, after a signed grant allows the
request. The workload never receives the credential.

```bash
env | grep STRIPE      # nothing

zs login
zs run npm dev         # the app calls api.stripe.com. it works.
```

## What ZeroSecret claims

<!-- CLAIM-FENCE-START -->

**Safe:** ZeroSecret removes standing credentials from supported local source trees,
`.env` files, shell startup files, and runtime configuration.

**Safe, strict mode:** on an intercepted path, the workload gets access without receiving
the upstream credential.

**Unsafe, never make it:** "no secret in any process, for any stack." "Developers never
manage credentials again." "Every action in every stack is checked and logged."

<!-- CLAIM-FENCE-END -->

`zs resources` reports the interception layer and the strict-mode label of each resource.
The limits are in [docs/SECURITY.md](docs/SECURITY.md).

## What is in this repository

This repository holds the open-source engine: the `zs` agent and CLI, the TLS interception
engine, the HTTP, PostgreSQL, MySQL, MongoDB and Redis protocol code, the materializer, the policy
evaluator, the audit primitives, `zs-verify` and the protocol conformance suite. The hosted
control plane, SSO federation, organizations and the dashboard are the commercial edition and
are not in this repository ([docs/PRODUCT.md](docs/PRODUCT.md) §8). Some sections below
describe how the agent works with a control plane.

| Document | Owns |
|---|---|
| [PRODUCT.md](docs/PRODUCT.md) | Invariant, category, claims, non-goals |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Planes, crates, data flow, budgets |
| [SECURITY.md](docs/SECURITY.md) | Trust boundaries, threat model, documented limits, reporting a vulnerability |
| [ROADMAP.md](docs/ROADMAP.md) | Phases and exit criteria |
| [DECISIONS.md](docs/DECISIONS.md) | Irreversible choices |

Working on this repository — human or agent — start at [AGENTS.md](AGENTS.md). Adapters for
other tools point at it: `CLAUDE.md`, `CODEX.md`, `GEMINI.md`,
`.github/copilot-instructions.md`.

## Build and test

The toolchain version is in `rust-toolchain.toml`.

```bash
cargo build --locked
cargo test --workspace --locked
```

The agent keeps its CA key in a native credential store, and so do the tests that start it:
the macOS Keychain, or on Linux a Secret Service on the D-Bus session bus. The CI workflow
starts a private bus with `gnome-keyring` for this. [CONTRIBUTING.md](CONTRIBUTING.md) lists
the checks a pull request must pass.

## Install a release binary

A release publishes `zs-<version>-<target>.tar.gz` (`.zip` on Windows), one CycloneDX SBOM per
target and a `SHA256SUMS` file, with a Sigstore keyless attestation for every file. The
targets are `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`,
`x86_64-apple-darwin` and `x86_64-pc-windows-msvc`.

```bash
version=0.6.0
target=x86_64-unknown-linux-gnu
repo=pewh/zerosecret-engine
gh release download "v$version" --repo "$repo" \
  --pattern "zs-$version-$target.tar.gz" --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS   # macOS: shasum -a 256 --check
gh attestation verify "zs-$version-$target.tar.gz" --repo "$repo"
tar -xzf "zs-$version-$target.tar.gz"
install -m 0755 zs ~/.local/bin/zs
```

On macOS, remove the quarantine attribute before the first run: `xattr -d com.apple.quarantine zs`.
The binaries are not code-signed (ADR-0055, DS3). The Linux binaries link `libdbus-1.so.3`
dynamically; the platform table below lists the runtime requirements.

## Run the conformance suite

The suite drives the agent against real PostgreSQL, MySQL, MongoDB and Redis servers in Docker
and against the AWS SigV4 test vectors. It needs Docker, the `mysql` client, `mongosh` and
`redis-cli` built with TLS (the `redis-tools` package on Debian and Ubuntu).

```bash
tools/db-test-certs.sh target/db-test-certs
docker compose --profile pgtls --profile mysql --profile mongo --profile redis up -d --wait \
  postgres postgres-tls mysql mongo redis redis-tls
tools/mongo-test-setup.sh
cargo build --locked -p zs
cargo run --locked -p zs-conformance -- run --config crates/zs-conformance/conformance.toml
```

The suite spec is [docs/specs/2026-10-26-conformance-suite.md](docs/specs/2026-10-26-conformance-suite.md).

## Licence and name

Apache-2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE). The name is covered by
[TRADEMARK.md](TRADEMARK.md): a fork that changes the code uses a different name. Report a
vulnerability as [docs/SECURITY.md](docs/SECURITY.md) describes, never in a public issue.

## Integrating an application

ZeroSecret provides commands for developers and AI coding agents to scaffold policy and strip secrets:

```bash
zs schema               # View JSON Schema for zs-policy.json
zs init                 # Scan .env, back it up to ~/.zs-backups/<project>/ (0600), and scaffold zs-policy.json
zs agent-instructions   # Print system prompt for AI coding agents
```

## Running an app with `zs login` and `zs run`

Put a `run` block in the app's `zs-policy.json`, and commit it with the control plane's CA
certificate:

```json
{
  "run": {
    "control": "http://127.0.0.1:8443",
    "control_ca": "zerosecret/control-ca.crt",
    "credentials_dir": "~/.zs-credentials/acme"
  },
  "bindings": [ ... ]
}
```

Then, from the app's root:

```bash
zs login               # SSO in the browser; again when the enrolment expires (7 days)
zs run -- npm start    # every time: no flags, no token
```

The `run` keys are `control`, `control_ca`, `credentials_dir`, `ca_dir` and `audit`. An
unknown key is refused. A flag (`--control`, `--control-ca`, `--credentials-dir`, `--ca-dir`,
`--audit`) wins over the file for its key. `~/` is your home directory. A relative path is
read from the directory that holds `zs-policy.json`. A `credentials_dir` in the file must be
below `~/.zs-credentials/`; a flag can name any directory. If `<ca-dir>/control-ca.crt` also
exists and differs from `control_ca`, `zs` stops.
[SECURITY.md §3](docs/SECURITY.md#3-what-zerosecret-does-not-defend-against) explains why
committed settings are limited.

`zs login` prints `zs: signing in to <control>`, then the sign-in URL and a code:
`zs: the browser must show code <CODE> for device <NAME>`. On macOS it opens the browser.
Check the control URL first. After you sign in, the browser page must show the same code and
device name. If it does not, close the page. `zs login` accepts `http://` only for
`localhost`, 127.0.0.0/8 and `::1`. Your subject must be a member of exactly one organization:

| Line | What to do |
|---|---|
| `zs: not a member of any organization; ask an admin to add <subject>` | Ask an admin to add you in the dashboard |
| `zs: member of several organizations; use an enrolment token` | Issue an enrolment token on the dashboard (the Devices page, or the page shown after you sign in) and use `zs run --enrollment-token` |

The enrolment lasts 7 days. `zs run` stops before it starts your command when the enrolment
is not usable:

| Line | What to do |
|---|---|
| `zs: not enrolled with <url>; run zs login` | Run `zs login`. You enrolled with another control URL, or not at all |
| `zs: control plane CA changed; run zs login` | Check that the new `control_ca` is correct, then run `zs login` |
| `zs: this device is no longer enrolled; run zs login` | The enrolment expired, or an admin deleted the device or removed your membership |
| `zs: control plane signing key changed; run zs login` | Run `zs login` |
| `zs: <resource>: binding host does not match the grant` | The binding's `host` or `protocol` differs from the resource on the control plane. Fix the binding |
| `zs: device record: secure storage locked` | Unlock the keychain or the Secret Service collection, then retry |
| `zs: <resource>: <field> is <file value> in the policy file, but the control plane signed <signed value>; ...` | Remove the field from the binding, or ask an admin to change the resource. See [Signed connection fields](#signed-connection-fields) |
| `zs: <resource>: upstream_ca <path> has SHA-256 <file hex>, but the control plane signed <signed hex>; ...` | Restore the CA file, or ask an admin to set the resource's CA SHA-256 to the new value |
| `zs: <resource>: the control plane signed a CA bundle with SHA-256 <hex>; set upstream_ca to that file` | Set `upstream_ca` in the binding to the CA file |

`zs status` prints `device: <id> (enrolled with <url> as <subject>)` or
`device: not enrolled`. `zs logout` removes the device record, `.zs-device.json` and
`.zs-session` on this machine. It does not tell the control plane: an admin deletes the device
in the dashboard.

`--enrollment-token` keeps the old path: a new enrolment for one run that is not saved. Its
subject also needs a `members` row.

## Integrating ZeroSecret into an existing repository

Copy and paste this instruction to an AI coding agent (Claude Code, Gemini, Cursor, Copilot) in the target application repository:

```text
Run `zs agent-instructions` and follow the protocol to integrate ZeroSecret into this repository.
```

### Agentic CLI Commands

| Command | Description |
|---|---|
| `zs agent-instructions` | Prints the zero-credential integration protocol for AI coding agents |
| `zs schema` | Outputs the Draft 2020-12 JSON Schema for `zs-policy.json` |
| `zs init [--dry-run] [--db PREFIX=protocol] [--auth KEY=bearer\|header:Name]` | Scans `.env`, writes a timestamped backup to `~/.zs-backups/<project>/` (directory `0700`, file `0600`, outside the repository), updates `.gitignore`, scaffolds `zs-policy.json`, writes each brokered value to `~/.zs-credentials/<project>/<resource>` (directory `0700`, file `0600`; an existing file with another value stops it before `.env` changes), and replaces the secrets it brokers with placeholders. It brokers database URLs, split database keys (`<P>_HOST` with `<P>_PASSWORD`; the listener takes the app's port), `<N>_URL` with a client id and secret or a user and password (HTTP Basic, one credential per host, never a loopback URL), three known APIs, and keys named with `--auth`. `--db` names the protocol when the prefix, port or dialect does not. It prints one `control plane resource` line per binding for the admin. Other secrets stay in `.env` and are listed by key name as "not brokered". `--dry-run` writes nothing and prints unbrokered values as `<withheld>`. A second run on a sanitized file is refused; restore the backup first |
| `zs doctor --json` | Outputs policy validation as JSON; a policy error is in `diagnostics` and exits 1 |
| `zs status --json` | Outputs session and device enrolment as JSON; exits 1 when signed out |
| `zs version` | Prints the build version, the commit, the UTC build time and the target triple; `zs --version` prints the same line |

Design: [agentic CLI spec](docs/specs/2026-10-22-agentic-cli.md), amended by [review fixes](docs/specs/2026-10-23-agentic-cli-review-fixes.md).

## Running the database locally

Start the disposable PostgreSQL database defined in `docker-compose.yml`:

```bash
rtk proxy docker compose up -d
rtk proxy docker compose exec -T postgres pg_isready -U postgres -d zerosecret_test
```

Tests need `DATABASE_URL` configured for this database on host port 5434, with database
`zerosecret_test`. Without it, some database-backed tests return early. On the maintainer's
Mac, start the existing Colima profile `zerosecret-db` only if Docker is unavailable and
that profile exists. This runbook does not remove stale locks or clean up machine state.

The control plane is the Go module in `control/`. Build it before the shared control-plane
tests:

```bash
(cd control && go build -o bin/control ./cmd/control)
```

The tests drive that binary; `ZS_CONTROL_BIN` names another one. The queries are generated
by `sqlc` from `control/migrations/0001_initial.sql`. After a schema or query change,
regenerate the checked-in code and commit it:

```bash
(cd control && go generate ./internal/store && go tool -modfile=tools/go.mod sqlc generate)
```

CI fails when the generated code does not match the source.

The real database tests use test certificates that a script writes into `target/`. MySQL
needs two MySQL 8.4 servers, one with TLS and one without. PostgreSQL TLS needs one
PostgreSQL 16 server with `ssl=on`. MongoDB needs one MongoDB 8.0 single-node replica set
with TLS allowed:

```bash
tools/db-test-certs.sh target/db-test-certs
rtk proxy docker compose up -d --wait mysql mysql-plain postgres-tls
rtk proxy docker compose up -d --wait mongo
tools/mongo-test-setup.sh
ZS_TEST_MYSQL=127.0.0.1:3307 ZS_TEST_MYSQL_PLAIN=127.0.0.1:3308 \
ZS_TEST_MYSQL_CERTS="$PWD/target/db-test-certs" \
cargo test -p zs-proto-mysql --test mysql_real -- --test-threads=1
ZS_TEST_PG_TLS=postgres://postgres:postgres@127.0.0.1:5435/zerosecret_test \
cargo test -p zs --test postgres_real tls_ -- --test-threads=1
ZS_TEST_MONGO=127.0.0.1:27018 ZS_TEST_MONGO_CERTS="$PWD/target/db-test-certs" \
cargo test -p zs-proto-mongo --test mongo_real -- --test-threads=1
```

The Redis broker tests need the three compose Redis services: `redis` (a password for the
default user and the ACL user `zs_app`), `redis-open` (no password) and `redis-tls` (TLS only,
the same users, certificates from `tools/db-test-certs.sh`). The Redis tests stop with a message
when a variable is missing:

```bash
tools/db-test-certs.sh target/db-test-certs
docker compose --profile redis up -d --wait redis redis-open redis-tls
ZS_TEST_REDIS_ADDR=127.0.0.1:6380 ZS_TEST_REDIS_PASSWORD=zs-test-redis \
ZS_TEST_REDIS_ACL_USER=zs_app ZS_TEST_REDIS_ACL_PASSWORD=zs-test-redis-acl \
ZS_TEST_REDIS_NOAUTH_ADDR=127.0.0.1:6381 \
ZS_TEST_REDIS_TLS_ADDR=127.0.0.1:6382 ZS_TEST_REDIS_CERTS=$PWD/target/db-test-certs \
cargo test -p zs-proto-redis --test redis_real -- --ignored --test-threads=1
```

`apps/zs/tests/redis_l3.rs` runs a real client through `zs run` against the same Redis. The
client is any command that reads `ZS_ORDERS_REDIS_HOST` and `ZS_ORDERS_REDIS_PORT` and exits
non-zero on failure; `ZS_TEST_REDIS_USER` binds an ACL user:

```bash
ZS_BUILD_TEST_ENDPOINTS=1 ZS_TEST_REDIS_ADDR=127.0.0.1:6380 ZS_TEST_REDIS_PASSWORD=zs-test-redis \
ZS_TEST_REDIS_CLIENT='redis-cli -h "$ZS_ORDERS_REDIS_HOST" -p "$ZS_ORDERS_REDIS_PORT" PING | grep -q PONG' \
cargo test -p zs --test redis_l3 a_real_client -- --ignored
```

Without their variables, the other real-server tests return early. The wrapper `tools/mysql-test-certs.sh` runs
`tools/db-test-certs.sh`. Run it with no argument, or with `target/db-test-certs`. The old
argument `target/mysql-test-certs` writes to a directory that compose no longer mounts.

The previous repository, `LayerFluxGovernance`, is frozen reference material. It is not
the target architecture and nothing is ported without a decision entry.

## HTTP bindings

An `https` binding (the default) or an `http` binding names its `host`, its `operations` and an
`auth` object. `operations: ["*"]` allows every HTTP method; it never allows `connect`
(ADR-0033). The default is `["GET"]`.

| `auth.scheme` | What the agent does |
|---|---|
| `bearer` (default) | Sets `Authorization: Bearer <credential>` |
| `basic` | Sets `Authorization: Basic <credential>`. Store the value already base64-encoded |
| `api-key-header` | Sets the header named by `header` |
| `query-param` | Sets the query parameter named by `param` |
| `websocket-json-field` | Replaces the string field named by `field` in the client's JSON WebSocket messages (ADR-0034) |
| `aws-sigv4` | Signs again with the secret, under `access_key_id`, `region` and `service`. A request with no `Authorization` header goes through unchanged (ADR-0035) |
| `hmac-body-signature` | Writes HMAC-SHA256 of `METHOD:<id_header value>:sha256(body):<secret>`, keyed with the secret, to `signature_header`. An empty body is signed as `{}` (ADR-0046) |

```json
{ "resource": "files", "host": "s3.eu-central-003.backblazeb2.com",
  "auth": { "scheme": "aws-sigv4", "access_key_id": "<key id>", "region": "eu-central-003", "service": "s3" },
  "local_endpoint": true, "operations": ["*"] }
```

- `protocol: "http"` sends the credential in cleartext to the upstream. `zs run` then also sets
  `HTTP_PROXY`. A request with the other scheme is denied (ADR-0033).
- An `http` binding gets a grant only from a control-plane resource whose protocol is `http`.
  With a control plane, a binding whose host or protocol differs from its grant stops the run at
  startup. In local mode the request is denied instead (ADR-0037).
- `local_endpoint: true` opens a loopback listener and sets `ZS_<RESOURCE>_URL`, for clients
  that ignore proxy variables. The URL carries the run token as its first path segment:
  `http://127.0.0.1:<port>/<token>`, so `POST <that url>/.zs/presign` needs no header. A request
  whose path does not start with the token gets `403`. It accepts only `Host: 127.0.0.1:<port>`
  or `localhost:<port>` and refuses a request with `Origin`. `POST <url>/.zs/presign` with
  `{"url": ..., "method": ...}` answers with the presigned URL signed by the real secret, on
  the public origin; `X-Amz-Date` must be within 15 minutes of now (ADR-0035). A `url` that a
  client presigned on `ZS_<RESOURCE>_URL` keeps the token as its first path segment; the agent
  removes it before it signs, so the answer never carries the token.
- `zs run` adds `127.0.0.1,localhost,::1` to `NO_PROXY`, and points `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` at `ca-bundle.crt` (the agent CA and the system
  roots).
- `HTTPS_PROXY` carries the run token as the proxy user name and password:
  `http://zs:<64 hex>@127.0.0.1:<port>`. A client that drops the userinfo is refused with `407`
  and never reaches a grant, a credential or the audit journal. There is no opt-out flag, and the
  token changes on every run; it is never written to disk or printed (ADR-0052).

## Database upstream TLS

The agent asks the upstream for TLS before it sends a credential. For PostgreSQL, it sends an
SSLRequest. For MySQL, it reads the TLS flag in the server greeting and asks for TLS when the
flag is set.

| Binding fields | Server offers TLS | Server does not offer TLS |
|---|---|---|
| none | Verify with the webpki roots and the name | Plaintext |
| `upstream_ca` | Verify with the webpki roots, these certificates and the name | Refuse |
| `upstream_cert_sha256` | Accept only this leaf certificate. No name, chain or date check | Refuse |

- The name is `upstream_host` when it is set, else `host`.
- A TLS failure never falls back to plaintext. A PostgreSQL client gets
  `upstream TLS failed` (SQLSTATE 08006) for each TLS refusal: a failed verification or pin,
  `N` when a TLS field is set, a bad answer byte, a byte after `S`, or a close or reset during
  the TLS handshake. It gets `upstream unavailable` (SQLSTATE 08006) when the SSLRequest
  exchange fails, the agent sees a close before the handshake, or the TLS negotiation times
  out. A MySQL client gets `ZeroSecret upstream TLS failed`.
- `upstream_ca` is a PEM file. A relative path is read from the working directory of `zs run`.
  `upstream_cert_sha256` is the SHA-256 of the DER leaf certificate, 64 hex digits.
  Do not set both `upstream_ca` and `upstream_cert_sha256`: `zs run` stops at load.
- `upstream_plaintext` is for `https` bindings (loopback only), and `mongo` and `redis` bindings
  (any host). On a `postgres` or `mysql` binding, `zs run` stops at load.
- Change for `postgres` bindings (ADR-0030): the agent refuses a server that offers TLS with a
  private CA, for example every AWS RDS server, until the binding sets `upstream_ca` or a pin.
  Before, the agent connected in plaintext.

### MongoDB

MongoDB does not negotiate TLS. A `mongo` binding uses TLS unless it sets
`upstream_plaintext: true`.

| Binding fields | MongoDB upstream |
|---|---|
| none | TLS. Verify with the webpki roots and the name |
| `upstream_ca` | TLS. Verify with the webpki roots, these certificates and the name |
| `upstream_cert_sha256` | TLS. Accept only this leaf certificate. After a redirect the primary's leaf must match the pin too, so a set with one leaf per member needs `upstream_ca` |
| `upstream_plaintext: true` | Plaintext. SCRAM still never sends the password |

A `mongo` binding needs `user`. `auth_source` is optional (default `admin`). Point the client at
`ZS_<RESOURCE>_HOST` and `ZS_<RESOURCE>_PORT` with no user name, no password and no `tls`
option. The client sees a replica set with one member, the listener. All reads go to the
primary. A client that sends credentials gets `zs: authentication is brokered`.

```json
{ "resource": "orders-mongo", "host": "mongo.example.internal", "protocol": "mongo",
  "user": "app", "auth_source": "appdb" }
```

### Redis

A `redis` binding uses TLS unless it sets `upstream_plaintext: true`. The agent opens the
upstream connection and sends `AUTH [<user>] <credential>` before it reads a client frame; TLS
comes first unless the binding is plaintext.

| Binding fields | Redis upstream |
|---|---|
| none | TLS. Verify with the webpki roots and the name |
| `upstream_ca` | TLS. Verify with the webpki roots, these certificates and the name |
| `upstream_cert_sha256` | TLS. Accept only this leaf certificate. No name, chain or date check |
| `upstream_plaintext: true` | Plaintext. The session carries the credential in `AUTH` |

`user` is optional. When the binding leaves it out, the listener accepts only `default`, and the
agent authenticates as `default`. Point the client at `ZS_<RESOURCE>_HOST` and
`ZS_<RESOURCE>_PORT` with no password. The listener is plaintext loopback and refuses client TLS.
The agent rewrites every `AUTH`, and the `AUTH` arguments of `HELLO`, to the binding user and the
credential; it never forwards the client's password. A client that names another user, sends a
non-RESP frame or meets a cluster redirect gets a fixed `-ERR` and the connection closes. A
`HELLO` with a second `AUTH` clause is refused. An empty line between frames is skipped, as Redis
does, and the replies to frames sent before a refused one arrive before the error. A one-argument `AUTH` carries no password and is
forwarded; an `AUTH` with four or more arguments is refused. A handshake that exceeds 15 seconds
answers `-ERR ZeroSecret upstream unavailable` and audits `deny` `connect`, reason
`handshake timed out`.

```json
{ "resource": "orders-redis", "host": "redis.example.internal", "protocol": "redis",
  "user": "app" }
```

A Redis with no password (a development server) is refused unless the binding sets
`upstream_auth_optional: true` (ADR-0058). The agent still sends its `AUTH` first, so the binding
still needs a credential; any value works against an open server:

```json
{ "resource": "orders-redis", "host": "redis.example.internal", "protocol": "redis",
  "upstream_auth_optional": true }
```

Give the brokered user no admin rights, so the client cannot read or change the credential:
`ACL SETUSER app on >… ~* &* +@all -@admin -@dangerous +info`. `INFO` is in `@dangerous`, and
the ioredis ready check and Bull need it.

### AWS RDS behind a DNS alias

The RDS certificate names the RDS endpoint, not your alias. Set `upstream_ca` to the RDS
bundle (`https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`) and
`upstream_host` to the endpoint name from the certificate. The agent connects to
`upstream_host`, so that name must resolve on the machine that runs `zs run`. The application
still connects to the local listener. With a control plane, an admin also sets the resource's
upstream host and CA SHA-256 in the dashboard (see [Signed connection fields](#signed-connection-fields)).

```json
{
  "resource": "orders-pg",
  "host": "orders-db.internal.example",
  "upstream_host": "orders.abc123xyz.ap-southeast-3.rds.amazonaws.com",
  "protocol": "postgres",
  "upstream_ca": "rds-global-bundle.pem"
}
```

To read the endpoint name from the certificate (OpenSSL 3; LibreSSL has no
`-starttls postgres`):

```bash
openssl s_client -starttls postgres -connect orders-db.internal.example:5432 </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

If you cannot use the name, pin the leaf with `upstream_cert_sha256`. Change the pin when RDS
rotates the certificate.

## Signed connection fields

With a control plane (`zs login` or `--enrollment-token`), the control plane signs how the agent
reaches each resource (ADR-0038). An admin sets the values per resource in the dashboard. Empty
means the default:

| Binding field | Signed as | Default |
|---|---|---|
| `upstream_host` | `upstream_host` | the resource `host` |
| `upstream_port` | `upstream_port` | https 443, http 80, postgres 5432, mysql 3306, mongo 27017, redis 6379 |
| `upstream_plaintext: true` | `upstream_tls` `plaintext` | `default` |
| `upstream_ca` | `upstream_tls` `ca-sha256:<hex>` | `default` |
| `upstream_cert_sha256` | `upstream_tls` `pin-sha256:<hex>` | `default` |
| `local_endpoint: true` | `local_endpoint` | `false` |

- A binding may leave these fields out and take the signed values. A field it sets must equal
  the signed value, or `zs run` stops before it starts your command. The stop line names the
  field, the file value and the signed value.
- `upstream_ca` stays a file in the repository. The admin enters only its hash, which
  `zs ca-sha256 <file>` prints. The hash covers the certificates in the file, so line endings
  and comments do not change it. `shasum -a 256` of the file is not the same value.
- `auth`, `listen_port`, `paths`, `user`, `auth_source` and `client_auth_plugin` stay in the
  file and are not signed ([SECURITY.md §3](docs/SECURITY.md#3-what-zerosecret-does-not-defend-against)).
- The connection is fixed when `zs run` starts. After an admin changes it, restart `zs run`.
  Until then, renewals print
  `zs: <resource>: the control plane changed <field> (signed <value>, running <value>); restart zs run to use it`.
- An https or http binding gets requests on its signed port or on the protocol default only.
  Another port is denied with `port <n> is not the signed port <m>`.
- `zs resources` prints `connection (control plane, display only): <summary>` for each binding,
  or `connection: signed at run time` without an enrolment, when the fetch fails, or when the
  control plane has no resource of that name. Only the grant decides.
- In local mode (no control URL) the file signs its own grants. Each grant carries the four
  signed fields, and a request is denied when they differ from the binding.

**Upgrade.** A resource that existed before this change signs the defaults. A binding that sets
a non-default value (a port, `upstream_plaintext`, `upstream_ca`, a pin, `local_endpoint`, or an
`upstream_host`) stops after the upgrade until an admin sets that value. An admin sets the
values before or right after upgrading `zs` and `control`. The stop line says which field and
which value.

## Advertised wire URL

`ZS_CONTROL_WIRE_URL` sets the wire URL that the control plane gives a device at
enrolment. Set it when devices reach the wire listener at a different address than
`ZS_CONTROL_WIRE_ADDR`, for example behind NAT or a load balancer. If it is not set, the
URL is `https://<ZS_CONTROL_WIRE_ADDR>`. A wire address with an IPv6 zone, such as
`[fe80::1%en0]:8444`, cannot be advertised; set `ZS_CONTROL_WIRE_URL` for it.

The value must be an HTTPS origin:

- Accepted: `https://` followed by a DNS name, an IPv4 address, or a bracketed IPv6
  address. It can include a port from 1 to 65535 and one trailing slash. Examples:
  `https://control.example.com`, `https://10.0.0.5:8444/`, `https://[::1]:8444`.
- Rejected:
  - any scheme other than `https`;
  - user information, including an empty `@`;
  - a path, including `/base`, `/a/..` and `//`;
  - a query or a fragment, including an empty `?` or `#`;
  - port 0, or a port above 65535;
  - a URL with no host;
  - whitespace, control characters or backslashes.

The value is not resolved, and its port does not have to match the bound port. Port 443
is removed from the published URL.

Migration: before this change, the control plane accepted some malformed values, such as
a value with a path prefix or with user information. It now refuses to start with them,
and prints `control: listen: invalid advertised wire URL`. The message does not include
the value. Remove the path, query, fragment or user information. The wire routes are
always served at the root of the origin.

## Dashboard admins

The dashboard has two roles, `admin` and `member`
(ADR-0042). Any member of the dashboard organization reads every page.
Only an admin changes anything. A member can still issue an enrolment token for their own
devices.

`ZS_CONTROL_ADMINS` sets the first admins. It is a comma-separated list of subjects, for example
`ZS_CONTROL_ADMINS=ana@example.com,ben@example.com`. The subject is the `email` claim of the
sign-in when the ID token also carries `email_verified: true`, and `sub` otherwise. An
`email_verified` that is not a JSON boolean, such as the string `"true"`, refuses the sign-in.
The match is exact, case included.

An IdP that does not send `email_verified` always signs in by `sub`. Microsoft Entra ID is one: it
omits the claim by default, so a user there is identified by their `sub` value, and
`ZS_CONTROL_ADMINS` must list `sub` values, not email addresses. Keycloak sets the claim from the
user's `emailVerified` flag; mark the demo-style users verified.

- At startup, `control` makes each listed subject an `admin` of the dashboard organization. When
  the variable lists at least one subject, `control` also prints
  `control: dashboard admins from ZS_CONTROL_ADMINS: <count>`. It prints nothing when the
  variable is unset or empty.
- A listed admin is pinned. The dashboard cannot demote or remove it, and a rename is refused too.
- The variable only adds admins. When you remove a name from it, that subject is no longer
  pinned, but it stays `admin` until another admin changes it.
- An item that is empty, has a control character or a comma, or is longer than 320 bytes stops
  `control` with exit 1 and `control: ZS_CONTROL_ADMINS: item <n>: <reason>`. The line gives the
  position of the item, not its value.
- Without an admin, `control` still starts and prints
  `control: no dashboard admin in <org>; set ZS_CONTROL_ADMINS`. Devices still enrol and get
  grants.
- Recovery when every admin is lost: set `ZS_CONTROL_ADMINS` and restart `control`.

Upgrade: on an existing deployment, the first start with this version changes member roles other
than `admin` (for example `owner` or `Admin`) to `member`. It also deletes pending approvals that
have no organization. Until you set `ZS_CONTROL_ADMINS` and restart `control`, nobody can write in
the dashboard, and every member can only read.

[SECURITY.md §3](docs/SECURITY.md#3-what-zerosecret-does-not-defend-against) owns the limits.

## Local CA storage

`zs run` loads its local CA from the CA directory: `.zs-ca` in the current directory,
`run.ca_dir` in `zs-policy.json`, or the path given with `--ca-dir`, which wins. The private
key is kept only in the platform's native secure store.
[SECURITY.md §6](docs/SECURITY.md#6-tls-and-the-local-ca) owns the rules and limits; this
section tells you how to operate it.

The CA directory holds three files. None of them holds the private key.

| File | Role |
|---|---|
| `ca.crt` | The public CA certificate. Trust stores need it |
| `.ca-storage-id` | Public metadata: 32 hex digits that name the native record. It is not a secret. Do not edit it, and do not copy it into another CA directory: two directories with the same ID name one record, so their agents can race on it, and on Windows a write can overwrite it |
| `.ca-storage.lock` | The lock that serializes agents that start against the same directory |

### Platform prerequisites

This is CA key storage. It is not a claim of full product support on Linux or Windows.

| Platform | Prerequisite |
|---|---|
| macOS | An unlocked default keychain. The agent uses `/usr/bin/security`. It checks the lock first and stops within 5 s if the keychain is locked, instead of waiting out an unlock prompt. Each call stops after 30 s, or after `ZS_KEYCHAIN_TIMEOUT_SECS` whole seconds (1 to 300) |
| Linux | To build: the libdbus-1 development files and `pkg-config` (on Debian or Ubuntu, `libdbus-1-dev pkg-config`). To run: the `zs` binary links `libdbus-1.so.3` dynamically, so every `zs` subcommand needs that library installed (on Debian or Ubuntu, `libdbus-1-3`) before it can load; `control` does not. `zs run` also needs a session D-Bus and a Secret Service provider, such as GNOME Keyring, with an unlocked default collection. The agent never unlocks or creates a collection, so a headless or WSL host without one cannot start the agent |
| Windows | Credential Manager for the signed-in user |
| Other | Not supported. The agent stops before it starts the command |

### Errors

A CA failure prints `zs: local ca: ca storage: <message>`, exits with status 1, and does not
start your command. The message is fixed text. It never contains a key or native error
text. No failure replaces a key or mints a new CA, and `zs run` never deletes a record.

You can retry these after you fix the cause:

| Message | Cause and action |
|---|---|
| `secure CA storage locked` | The macOS default keychain or the Linux default collection is locked. The agent does not wait for an unlock prompt. Unlock it, for example with `security unlock-keychain` on macOS, then retry. Nothing in the CA directory changed |
| `secure CA storage unavailable` | The native store is denied, unavailable, timed out, or ambiguous, or a file in the CA directory could not be read or written. Unlock any other keychain in the macOS search list, or start the Secret Service, then retry. On macOS, a keychain that locks during a first start can leave `.ca-storage-id` behind. That is expected. Keep the file; the next start uses it |
| `CA storage timeout invalid` | `ZS_KEYCHAIN_TIMEOUT_SECS` is not a whole number of seconds from 1 to 300. Fix or unset it |
| `CA storage busy` | Another agent is loading the same CA directory. Retry when it has started |
| `CA certificate publication failed` | `ca.crt` could not be written. Fix the directory permissions, then retry. The next start writes `ca.crt` from the native record |
| `CA legacy key removal failed` | The key is stored, read back and validated, but the old copy is not yet removed. Retry. The next start removes the old copy if it remains |
| `secure CA storage unsupported` | The platform has no supported native store. Use macOS, Linux or Windows |

These need your decision. The agent does not repair them for you:

| Message | Cause and action |
|---|---|
| `CA private key missing` | `ca.crt` and `.ca-storage-id` exist, but the native record does not. Restore the record from a backup of the native store. Otherwise retire this directory, use a new CA directory, and trust its new `ca.crt` |
| `CA storage identity missing` | `ca.crt` exists, but `.ca-storage-id` and any legacy key do not. Restore `.ca-storage-id` from a backup if its native record still exists. On macOS, a directory that earlier versions created and that has not migrated yet finds its old Keychain item by its canonical path, so moving or renaming it hides that item and gives this error: move it back, start the agent once there to migrate, then move it. Otherwise act as for `CA private key missing` |
| `CA legacy identity incomplete` | An old key exists, but `ca.crt` does not. See [A legacy key without `ca.crt`](#a-legacy-key-without-cacrt) |
| `CA legacy key mismatch`, `CA legacy key invalid` | An old key does not match `ca.crt`, or it is not a valid key. Restore the matching pair from a backup, or retire the directory |
| `CA certificate mismatch`, `CA certificate invalid` | `ca.crt` does not match the native record, or it is not a valid certificate. Restore the correct `ca.crt`, or retire the directory |
| `CA storage record malformed`, `CA storage record invalid` | The native record is damaged. Restore it from a backup of the native store, or retire the directory |
| `CA storage readback mismatch` | The record did not read back as it was written. Retry once. If it fails again, retire the directory. During a migration the old key, `ca.key.pem` or the macOS Keychain item, may still be the only copy of the key: back it up before you retire the directory |
| `CA storage identity malformed` | `.ca-storage-id` is not 32 lowercase hex digits. Restore it from a backup |
| `CA storage path invalid` | One of `ca.crt`, `ca.key.pem`, `.ca-storage-id` or `.ca-storage.lock` is not a regular file, for example a symbolic link. Replace it with the real file |
| `CA generation failed` | A new CA could not be generated. Retry. If it continues, report it |

To retire a directory, run `zs ca retire` as the next section shows, then delete the
directory. If you delete `ca.crt` and `.ca-storage-id` some other way, the old record stays
in the store as an orphan, and the next start creates a new CA under a new record.

### Retiring a CA directory

```sh
zs ca retire --ca-dir <ca-dir> --yes
```

This deletes the directory's CA private key for good. Every client that trusts its `ca.crt`
stops trusting the agent and must trust a new CA. There is no default directory, and
without `--yes` the command only explains itself and exits 2. On success it prints `zs:
retired CA directory <ca-dir>: native record, ca.crt and .ca-storage-id removed`. The
directory and its `.ca-storage.lock` stay: delete them yourself. The next `zs run` against
the same directory creates a new CA.

Retire deletes only the one record that `.ca-storage-id` names, and only after it has read
that record and matched it against `ca.crt`. `<ca-dir>` must be the directory itself, not
a symbolic link to it. If another directory holds a copy of this `.ca-storage-id`, it names
the same record, so retiring either one deletes the key of both. A failure prints `zs: local ca: ca storage:
<message>` and exits 1. Besides the start messages above, these are retire-only:

| Message | Cause and action |
|---|---|
| `CA migration incomplete` | An old key copy remains: `ca.key.pem`, or on macOS the directory's pre-record Keychain item. Run `zs run` once against the directory to migrate it, then retire |
| `CA record removal failed` | The delete failed, or the read that must prove the record gone failed or found it. Both files are kept. Retry. If the record is gone by then, the retry reports `CA private key missing` |
| `CA directory cleanup failed` | The record is deleted, but `ca.crt` or `.ca-storage-id` could not be removed. Delete the directory yourself |
| `CA private key missing` | The record named by `.ca-storage-id` does not exist, so nothing native is left. Delete the directory |

### Removing an orphaned CA record

A directory that was deleted without `zs ca retire` leaves its `zerosecret.ca.v1` record
behind, and retire cannot find it without `.ca-storage-id`. Remove such a record only by
its exact account, from a backup of that `.ca-storage-id`. Do not remove records by
prefix. If you remove the record of a directory that is still in use, its next start fails
with `CA private key missing`. Use `zs ca retire` for any directory that still exists.

The account must be exactly 32 lowercase hex digits, because an empty account could match
the record of a different directory. Each command below reads the account from
`<id-file>`, your copy of that directory's `.ca-storage-id`, checks it, and runs the delete
only if the check passes.

- macOS. Exit status 44 means the record is already absent.

  ```sh
  account=$(cat <id-file>) &&
    case $account in *[!0123456789abcdef]* | '') false ;; *) [ ${#account} -eq 32 ] ;; esac &&
    security delete-generic-password -a "$account" -s zerosecret.ca.v1
  ```

- Linux. `secret-tool` is in the libsecret tools package.

  ```sh
  account=$(cat <id-file>) &&
    case $account in *[!0123456789abcdef]* | '') false ;; *) [ ${#account} -eq 32 ] ;; esac &&
    secret-tool clear service zerosecret.ca.v1 account "$account" schema 1
  ```

- Windows. Read the 32 hex digits in `.ca-storage-id`. In Credential Manager, open Windows
  Credentials, find the generic credential `zerosecret.ca.v1/<account>`, and select
  Remove.

### A legacy key without `ca.crt`

An old key is `ca.key.pem` in the CA directory or, on macOS, the Keychain item that earlier
versions wrote. The agent migrates an old key only when the matching `ca.crt` is present. If
`ca.crt` is missing, every start fails with `CA legacy identity incomplete` until you act.

1. If you have the original `ca.crt` of this directory, put it back. The next start
   migrates the key and keeps the same CA, so clients that trust it keep working.
2. If you do not have it, the old key cannot be migrated. Remove only that old key. The next
   start then creates a new CA, and clients must trust the new `ca.crt`.
   - `ca.key.pem`: move it out of the CA directory. It is a plaintext private key, so
     destroy it when you no longer need it.
   - The macOS Keychain item: its account and service are both
     `zerosecret-local-ca-` plus the first 16 hex digits of the SHA-256 of the directory's
     canonical path. This command computes that exact name and deletes that one item. It
     stops if it cannot enter the directory, so it never computes a name from an empty
     path:

     ```sh
     dir=$(cd <ca-dir> && pwd -P) && [ -n "$dir" ] &&
       label="zerosecret-local-ca-$(printf '%s' "$dir" | shasum -a 256 | cut -c1-16)" &&
       security delete-generic-password -a "$label" -s "$label"
     ```

### The shared Keychain item of the default `.zs-ca`

Earlier versions on macOS named the Keychain item of a CA directory before they created the
directory. For the default `--ca-dir .zs-ca`, every first run in a new project therefore
wrote its key under one shared name: `zerosecret-local-ca-` plus the first 16 hex digits of
the SHA-256 of the text `.zs-ca` itself, which is `zerosecret-local-ca-db1f16dd93727acd`.
That item is tied to no single directory: each such first run replaced it. The current
agent never reads or deletes it, because a CA directory that does not exist yet has no old
key. It is still a CA private key that a client may trust, so delete it once no client needs
that CA.

Caution: for a default project that an earlier version started only once, this item can be
the only copy of that project's CA key. Deleting it loses that CA for good, and every client
that trusts it must then trust a new one. Back the item up first, or confirm that no client
trusts that CA. This command computes the exact name and deletes that one item. Exit
status 44 means it is already absent.

```sh
label="zerosecret-local-ca-$(printf '%s' .zs-ca | shasum -a 256 | cut -c1-16)" &&
  [ "$label" = zerosecret-local-ca-db1f16dd93727acd ] &&
  security delete-generic-password -a "$label" -s "$label"
```

## Secret scanning

CI installs gitleaks 8.30.1 from its checksummed release and runs gate 2 of
`tools/public-gates.sh` over exactly the files this repository publishes: every file except
`.git` and `target`. The committed `.gitleaks.toml` extends the default rules and allows two
narrow sets of known false positives — the vendored SigV4 vectors, by path, and a short list
of synthetic values in this file and the tests, by exact pattern. There is no `.gitleaksignore`,
and the tree carries no inline `gitleaks:allow` marker.

Run the same gate locally before you push:

```bash
tools/public-gates.sh
```

To scan the history a `git log` reader would see, which the release gate does not:

```bash
gitleaks git --redact --no-banner --ignore-gitleaks-allow .
```

`.gitleaks.toml` decides what the gate accepts, so a change to it deserves the same review as
code. When a new synthetic test credential trips a rule, confirm it is synthetic and add its
exact value. Never allowlist a real credential; rotate it instead.
