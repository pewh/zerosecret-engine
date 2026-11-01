# Contributing

## How changes reach this repository

The maintainers develop ZeroSecret in a private upstream repository. Each release arrives here as
one commit. When a maintainer accepts a pull request, they apply it upstream by hand, and the
change appears in the next release commit. The pull request is not merged directly.

## Sign off your commits

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/).
There is no contributor licence agreement. Sign off every commit:

```sh
git commit -s
```

The sign-off adds a `Signed-off-by: Your Name <you@example.com>` line. It states that you wrote
the change, or have the right to submit it under the Apache-2.0 licence.

## Build and test

The toolchain version is in `rust-toolchain.toml`.

```sh
cargo build --locked
cargo test --workspace --locked
```

Run these before you open a pull request. CI runs the same commands:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings -A clippy::unwrap_used -A clippy::expect_used -A clippy::panic
cargo deny check
```

## Run the conformance suite

The suite runs the `zs` agent against real PostgreSQL, MySQL and MongoDB servers in Docker. It
also needs the `mysql` client and `mongosh` on your `PATH`.

```sh
tools/db-test-certs.sh target/db-test-certs
docker compose --profile pgtls --profile mysql --profile mongo up -d --wait postgres postgres-tls mysql mongo
tools/mongo-test-setup.sh
cargo build --locked -p zs
cargo run --locked -p zs-conformance -- run --config crates/zs-conformance/conformance.toml
```

## Security reports

Do not open a public issue for a vulnerability. See [docs/SECURITY.md](docs/SECURITY.md). Never
put a credential value in an issue, a pull request, a log or a test.
