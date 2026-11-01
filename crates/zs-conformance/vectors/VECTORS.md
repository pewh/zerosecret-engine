# AWS SigV4 test vectors

Source: `https://github.com/awslabs/aws-c-auth`, tag `v0.9.0`, path
`tests/aws-signing-test-suite/v4`.

Retrieved: 2026-10-27, as the release tarball
`https://codeload.github.com/awslabs/aws-c-auth/tar.gz/refs/tags/v0.9.0`.
The tarball SHA-256 is
`aa6e98864fefb95c249c100da4ae7aed36ba13a8a91415791ec6fad20bec0427`.

The files are copied unchanged from the tarball. The tree holds 38 case
directories and 380 files. Each case holds the same ten files:

| File | Holds |
|---|---|
| `request.txt` | the request line, the headers and the body to send |
| `context.json` | the credentials and the signing time |
| `header-canonical-request.txt` | the canonical request AWS expects for header signing |
| `header-string-to-sign.txt` | the string to sign AWS expects |
| `header-signature.txt` | the signature AWS expects |
| `header-signed-request.txt` | the request with the expected `Authorization` header |
| `query-canonical-request.txt` | the canonical request for query signing |
| `query-string-to-sign.txt` | the string to sign for query signing |
| `query-signature.txt` | the signature for query signing |
| `query-signed-request.txt` | the presigned URL AWS expects |

Licence: Apache License 2.0. `LICENSE` and `NOTICE` are vendored next to the
vectors, copied from the same tarball.

## Why this source

The standalone repository `github.com/awslabs/aws-sig-v4-test-suite` returns 404
since before 2026-10-27. `awslabs/aws-c-auth` carries the same suite as the
component that signs for the AWS C SDK, and it is the source the maintained
`aws-sigv4` Rust crate takes its copy from.

Cross-check, 2026-10-27: the copy shipped in `aws-sigv4` 1.6.3 holds the same
cases, with three differences. It adds the two old-format cases
`double-encode-path` and `double-url-encode`. One file differs,
`get-space-normalized/request.txt`. This directory follows `aws-c-auth` v0.9.0,
so it holds neither addition.

## Folding

One case, `get-header-value-multiline`, writes one header value over three lines,
with a leading space on the second and third. HTTP/1.1 forbids that folded form
since RFC 7230, and neither `curl` nor the proxy's `hyper` reader accepts it. The
suite joins the continuation lines with a single space before it replays the
case, which is the value the case's own canonical request names
(`my-header1:value1 value2 value3`). The fold itself reaches no server; the
whitespace collapse the case asserts still runs.

## Two rules for one request

AWS ships a `-normalized` and an `-unnormalized` variant for seven requests, because
services differ on whether the signer resolves dot segments and repeated slashes.
Amazon S3 signs the path as sent. The suite replays one vector per pair and accepts
the canonical request of either rule, then reports which one matched. The current
implementation takes the S3 rule for six pairs; in the seventh both variants name
the same canonical request.

## How the suite reads them

Nothing is fetched at test time. `src/cases/sigv4.rs` reads `request.txt`,
`header-canonical-request.txt`, `header-string-to-sign.txt` and
`header-signature.txt` from this directory and replays the request through the
adapter under test.
