# zs-conformance

The conformance suite for a secretless proxy. Real `psql`, `mysql`, `mongosh` and `curl`
clients reach real PostgreSQL, MySQL and MongoDB fixtures and a fake SigV4 upstream through
the implementation under test. Each positive case also runs with a corrupted credential, and
where the upstream has a TLS identity, with a wrong upstream CA. Both controls must be
refused, or the case fails.

The suite never starts a proxy. It calls a shell adapter that prints back a local endpoint,
so the same cases run against any implementation.

## Run it against ZeroSecret

```sh
tools/db-test-certs.sh target/db-test-certs
docker compose --profile pgtls --profile mysql --profile mongo up -d --wait \
  postgres postgres-tls mysql mongo
tools/mongo-test-setup.sh
cargo build -p zs
ZS_CONFORMANCE_MYSQL_ADMIN=zs_admin:zs-test-admin \
  cargo run -p zs-conformance -- run --config crates/zs-conformance/conformance.toml
```

The adapter starts `zs run` for every case. On macOS that reads the login keychain, and on
Linux the Secret Service. `cargo test -p zs-conformance` runs the unit tests and the
extraction-seam tests; the cases themselves run through the `run` subcommand.

Every run prints a markdown matrix and writes `target/conformance/report.json`. The exit code
is 0 only when every case passed and none skipped.

## Point it at another implementation

Write an executable that implements the adapter contract below, then a config that names it:

```toml
[implementation]
name = "other"
adapter = "adapters/other.sh"
capabilities = ["postgres", "mysql"]

[fixtures]
postgres = "127.0.0.1:5434"
mysql = "127.0.0.1:3307"
```

A fixture that is absent makes its cases `SKIPPED` with the compose command to start it, and
the run exits non-zero unless `--allow-skips` is passed. CI never passes it. A protocol that is
not in `capabilities` is also `SKIPPED`, never passed, so the exit code stays non-zero.

## The adapter contract

Two subcommands, line-oriented, from the spec:

```
<adapter> setup --protocol <postgres|mysql|mongodb|http>
                --case <CASE-ID>
                --upstream-host <host> --upstream-port <port>
                --credential-file <path>
                [--upstream-ca <path>] [--upstream-tls <default|plaintext|ca-sha256:HEX|pin-sha256:HEX>]
                [--operations <csv>] [--auth-scheme <name>] [--access-key-id <id>]
```

On success it prints one line of JSON to stdout and exits 0:

```json
{"handle":"opaque","endpoint":"127.0.0.1:54321","env":{"PGHOST":"127.0.0.1","PGPORT":"54321"}}
```

```
<adapter> teardown --handle <opaque>
```

The presign case uses one management subcommand:

```
<adapter> presign --handle <opaque> --url <absolute-url> --method <GET|PUT|...> [--expires <seconds>]
```

On success it prints one line of JSON to stdout and exits 0, `{"url":"https://..."}`.
`--expires` defaults to 600. The suite asks for a value above the implementation's cap and
expects the adapter to fail, then asks for one inside the cap.

`setup` must not print the credential; the suite scans both streams for it. A non-zero exit is
a case failure, not a skip. That holds for a negative control too: the refusal must come from
the client's connection, so an adapter that rejects a wrong CA or credential at `setup` fails
the control. `teardown` runs even when the case fails. The request carries no
upstream user name, so an adapter that needs one reads it from `--case` or its own config.

## What the suite owns

Three pieces that neither a fixture nor an adapter supplies:

- Fixture roles for PostgreSQL, MySQL and MongoDB, provisioned once per run and redacted from
  every report line.
- A fake HTTP upstream that recomputes the SigV4 signature from the secret it was given, so a
  case proves a signature rather than a swapped key id. It also reports the canonical request
  and string to sign it built.
- A throwaway CA for the wrong-CA control, generated per run.

The SigV4 vectors are vendored under `vectors/aws-sig-v4-test-suite`, with provenance in
`vectors/VECTORS.md`. Nothing is fetched at test time.

## The last run, 2026-10-27

29 cases run, 29 pass, 0 fail, 0 skip. Every control is refused.

| Case | Result | Control |
|---|---|---|
| PG-01 to PG-08 | PASS | wrongpass and wrongca refused |
| MY-01 to MY-08 | PASS | wrongpass and wrongca refused |
| MG-01 to MG-07 | PASS | wrongpass and wrongca refused |
| SV-01 to SV-06 | PASS | wrongpass refused |

`MG-06` sends a document nested 150 levels deep. The proxy refuses it now: `crates/zs-proto-mongo`
walks each client `OP_MSG` and closes the connection past 100 levels, which is MongoDB's
documented limit. The proxy stays up and the next ping succeeds.

`SV-05` sends a `PUT` whose body is marked `STREAMING-UNSIGNED-PAYLOAD-TRAILER`. The proxy
decodes the aws-chunked framing, signs the decoded payload and the upstream verifies it. A
checksum trailer becomes an `x-amz-checksum-*` request header; any other trailer name is
refused.

`SV-06` asks for a presigned URL above the endpoint's expiry cap and expects a refusal, then
for one inside the cap and replays it over TLS to the fake upstream. `X-Amz-Expires` is capped
at 15 minutes (`docs/SECURITY.md` §3), so a revoked URL cannot outlive the grant by more than
that.

SigV4 positives carry one control, not two. They run over a plaintext `http` binding, where
there is no upstream TLS identity to substitute.

The PostgreSQL fixture on 5434 does not serve TLS, so a wrong CA on it can only fail because
the server declines TLS. The wrong-CA control of every plaintext PostgreSQL case therefore runs
against the TLS fixture on 5435, where the refusal must come from certificate verification.

The table above predates the review of 2026-10-27, which tightened PG-02, PG-08, MY-01, MY-04,
MY-06, MY-07, MG-01, MG-02, MG-06, SV-04, SV-05, SV-06 and every control. Run the suite again
before quoting it.
