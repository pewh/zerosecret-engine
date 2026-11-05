# Agent Instructions

ZeroSecret engine: the `zs` agent, the interception engine, the protocol crates, the
materializer, the policy evaluator, the audit primitives, `zs-verify` and the conformance
suite. This repository is the upstream for that code (ADR-0050).

The commercial layer — the Go control plane, the dashboard and the `control/e2e` suite — is a
separate private repository that pins a release tag of this one (ADR-0051). Do not add
control-plane code, dashboard code, commercial tests or commercial configuration here.

## Source of truth

| Domain | Owner |
|---|---|
| Invariant, category, claims, non-goals | [docs/PRODUCT.md](docs/PRODUCT.md) |
| Planes, crates, data flow, budgets | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Trust boundaries, threat model, documented limits | [docs/SECURITY.md](docs/SECURITY.md) |
| Phases and exit criteria | [docs/ROADMAP.md](docs/ROADMAP.md) |
| Irreversible choices | [docs/DECISIONS.md](docs/DECISIONS.md) |

A decision has one owner; link to it, never restate it. Delete superseded content.

## Build and test

The toolchain is in `rust-toolchain.toml`. CI runs:

```bash
cargo build --locked
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings \
  -A clippy::unwrap_used -A clippy::expect_used -A clippy::panic
cargo deny check
```

- Agent tests need a native credential store: a private Secret Service on the D-Bus session
  bus on Linux, a disposable keychain on macOS. Never use a developer's login keychain.
- Native keychain tests are `#[ignore]` by default. Run them only against a disposable
  keychain that is the user default and the only search-list entry.
- Build the release binaries in their own step before `budget_latency` and `budget_footprint`.
  Those tests measure wall-clock budgets; a concurrent build makes them miss. Do not widen a
  budget to absorb build noise.
- `ZS_BUILD_TEST_ENDPOINTS=1` compiles the test endpoints. A release binary must not contain
  them; CI checks with `strings`.
- Compile-fail fixtures encode source line numbers. Review `.stderr` snapshots after any line
  movement; never add a blanket preamble.

The conformance suite (Docker and real PostgreSQL, MySQL and MongoDB) is in
[README.md](README.md#run-the-conformance-suite). Its spec is
[docs/specs/2026-10-26-conformance-suite.md](docs/specs/2026-10-26-conformance-suite.md).

## Hard rules

1. A new capability or a trust-boundary change starts with a spec in `docs/specs/` or an ADR.
2. Never `git commit`, `git tag`, `git push` or publish a release unless asked.
3. Fail closed: unknown resource, stale policy, unavailable audit sink deny.
4. Never let a credential value reach a log line, an audit record, an error message, a metric
   label or a panic payload. Credential types do not implement `Debug`, `Display` or
   `Serialize`.
5. Do not weaken a security claim to make a test pass. Claims are owned by
   [docs/PRODUCT.md](docs/PRODUCT.md) §7.
6. Keep verifier rejection text fixed; an error that echoes its argument can echo a secret.
7. Sign off every commit under the DCO: `git commit -s`.
8. This repository is public: never commit a credential, a private key, a customer name or a
   private hostname. The `gates` job scans for secrets on every change.
9. A published tag is an identity. Never retag or force-move one (ADR-0050 D4).

## Verification

- Security acceptance tests need positive activity before an absence assertion, and a negative
  control when the test claims that a credential or an unauthorized request fails.
- The evidence for the invariant is a `zs-verify` report, not "it compiles" or "the test
  passes".
- A public method with no direct caller is a question, not proof that the capability is unused.
- Compiler diagnostics are the first evidence. Use rust-analyzer or `cargo metadata` for types
  and callers; use `grep` for literals, config values and error text.
- Native storage tests delete the exact record their fixture created. Never dump, print or
  inspect a real credential store.

## Docs and decisions

- Every diagram is mermaid; no ASCII art, box-drawing characters or indented arrow chains.
  Tabular content uses a markdown table.
- `docs/specs/*.md` are immutable dated records; a later change is a new spec or an ADR.
- `docs/DECISIONS.md` is newest first; change a decision with a new entry, never by editing
  history.
- The five owner documents exist in both repositories and can drift. An engine-facing change
  to one is made here, and in the commercial copy when it describes the engine.
- There is no `STATE.md` or `JOURNAL.md`; the commit and the pull request carry the record.

## Scope discipline

- Smallest change that solves the request.
- No new abstraction until the third caller exists.
- No feature that does not serve the invariant in [docs/PRODUCT.md](docs/PRODUCT.md).
- Delete superseded docs; do not mark them "historical reference".

## Output contract

Refactor into the structure in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Write tight code.
No inline documentation or comments unless requested. Stop explanations after the code blocks.

## Communication

Apply ASD-STE100. State what changed, what you ran, and what is still risky. Correct the user
when they are wrong.
