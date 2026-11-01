# MongoDB document depth guard

Status: **built 2026-10-27 on the owner's instruction; plan not published**. Date: 2026-10-27.
Plan: the implementation plan (not published).
Evidence: conformance case MG-06 (`crates/zs-conformance/src/cases/mongodb.rs`); spike
notes on MongoDB libraries (not published) §"Deep nesting crashes the process"; `docs/specs/2026-10-26-conformance-suite.md`
§10.

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

## 1. Why

MG-06 sends a document nested 150 levels deep. The proxy relays it, the fixture accepts it, and
the case fails. MongoDB documents a limit of 100 levels of nesting. A proxy that passes a
deeper document to the server either relies on the server to reject it (the fixture does not,
for inserts) or carries a document its own future code cannot decode safely: the `bson` spike
showed `Document::try_from` aborts the process on 1,200 levels.

## 2. Behaviour

A client `OP_MSG` whose body or whose document-sequence sections nest deeper than the limit is
refused. The proxy closes that client connection and records a refusal with the diag reason
`document_depth`. It stays up and serves the next connection.

The limit is **100** levels. The top-level command document is depth 1, so an element document
that would be depth 101 is refused. The value is a constant, not configuration: it is the
server's documented rule, and a setting would let a deployment weaken it.

No reply packet is sent. MongoDB clients read a closed connection as a transport failure, which
is what the case accepts ("the connection is refused or an error is returned"), and it keeps
the change small. A later change may answer with an `ok: 0` document if a client is found to
retry badly.

## 3. Where

`crates/zs-proto-mongo/src/lib.rs`, in `client_to_upstream`, after the payload is read and the
command name is known, before anything is written upstream. The walk lives in
`crates/zs-proto-mongo/src/bson.rs` as an iterative function over the raw bytes, and the
section walk in `wire.rs`.

The relay stays byte-pass-through. The guard reads and skips, it never builds a `Doc`, so it
cannot recurse and cannot allocate per element.

## 4. Cost

One linear pass over each client `OP_MSG` body. A bulk insert pays a pass over its documents.
The pass is a byte walk with no allocation, and the relay already reads the same bytes.
Measured on 2026-10-27 in a debug build: 2.8 ms per pass over a 349 KB document of 20,000
elements, from iteration 10 of that loop. A 48 MB insert would cost roughly 140 ms in debug and
far less in release. A test keeps ten passes over that document under two seconds, so a change
that makes the walk quadratic fails CI. If a budget later shows the cost, the first
optimisation is to skip documents above a size that cannot carry user nesting.

## 5. Non-goals

- Answering with a MongoDB error document.
- Changing the read side, authentication, or the topology paths.
- A configurable limit, or a limit per collection or operation.
- Enforcing other BSON limits (document size, key count).

## 6. Open for the owner

1. Whether closing the connection is acceptable, or the guard must answer `ok: 0` with code
   10334. Closing is recommended for this step.
2. Whether the limit should match a future `bson` adoption exactly. 100 is the documented
   server limit and the number the case exercises.
