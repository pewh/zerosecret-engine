# Streamed SigV4 uploads

Status: **built 2026-10-27 on the owner's instruction; plan not published**. Date: 2026-10-27.
Evidence: conformance case SV-05; `docs/DECISIONS.md` ADR-0035; `docs/SECURITY.md` §7.

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

## 1. Why

The AWS SDK for JavaScript uploads a stream with
`x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER` and an aws-chunked body. The agent
refused every `STREAMING-` value, so an SDK stream upload could not use the proxy. SV-05 asserts
that the body reaches the upstream intact and signed.

## 2. Behaviour

When `x-amz-content-sha256` starts with `STREAMING-`:

1. Decode the aws-chunked body: a hexadecimal size with an optional `;chunk-signature=...`
   suffix, a CRLF, the chunk, a CRLF, repeated, then a zero size and an empty trailer.
2. Replace the body with the decoded payload.
3. Set `x-amz-content-sha256` to the SHA-256 of the decoded payload.
4. Remove `content-encoding` and `content-length`, and drop those names from the signed-header
   list if the client listed them.
5. Sign the request as any other request, over the decoded payload.

The upstream receives a plain body with a correct payload hash. `x-amz-decoded-content-length`
stays in the headers, signed or not, because it still describes the body and a client may have
signed it; a value that does not equal the decoded length is denied.

A trailer is read after the zero chunk. An `x-amz-checksum-*` header is lifted into the request
headers, so the upstream validates the same checksum against the same decoded payload.
`x-amz-trailer`, which declared a trailer that no longer exists, and `x-amz-trailer-signature`,
which was a placeholder, are removed, and `x-amz-trailer` leaves the signed-header list if the
client listed it. Any other trailer name is denied.

The client's chunk signatures are placeholders under ADR-0035 and are not verified. A size that
is not hexadecimal, a chunk that runs past the body, a missing terminator, an unexpected trailer
name, or a `content-encoding` that is not `aws-chunked` is denied with a reason that does not
echo the body.

## 3. Limits

- The body is buffered. `InjectedRequest` already holds every request body, so this adds no new
  buffering, but it is not a streaming proxy.
- The upstream receives no chunked framing, so a client that streams gigabytes pays memory for
  the whole body.
- Trailers are limited to `x-amz-checksum-*` headers. A trailer that carries anything else is
  refused.
- No `OP_COMPRESSED`, no HTTP/2, no chunk-signature verification.

## 4. Non-goals

- Preserving the chunked framing and re-signing each chunk.
- Validating the client's chunk signatures.
- Accepting trailers.

## 5. Open for the owner

1. Whether a trailer that carries a vendor checksum the agent does not know should pass
   through. It is refused today.
2. Whether the buffered decode is acceptable for the expected upload sizes.
