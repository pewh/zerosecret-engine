# Vendor-neutral HMAC body signature

Status: **accepted by the owner 2026-10-29, without an alias for the old name**. Date: 2026-10-29.
Decision record: ADR-0046 (written with the code). Supersedes the vendor-named scheme of ADR-0035.

## 1. Why

ADR-0035 added an `auth` scheme for one payment gateway, and the scheme carries the vendor's
name. The open-source release removes vendor names from the public engine (owner ruling
2026-10-29). The signing rule is generic HMAC and fits other APIs, so it gets a neutral name and
two settings in place of two hardcoded header names.

## 2. The scheme

A binding sets:

```json
"auth": { "scheme": "hmac-body-signature", "id_header": "va", "signature_header": "signature" }
```

| Field | Meaning |
|---|---|
| `id_header` | Required. The request header whose value enters the signed string. The client sends it |
| `signature_header` | Required. The header the agent writes the signature into |

For each request the agent:

1. Reads the value of `id_header`. If the request has no such header, the agent denies the
   request before the upstream with the fixed text `hmac-body-signature needs its id header`.
2. Takes the body. An empty body is replaced by the two bytes `{}`. The forwarded body does not
   change.
3. Builds `METHOD:<id value>:<sha256 hex of the body>:<secret>`, with `METHOD` in upper case.
4. Computes HMAC-SHA256 over that string, keyed with the secret, and writes it as lower-case hex
   to `signature_header`. A header of that name sent by the client is replaced, so exactly one
   remains.

The raw secret never goes on the wire. The bytes signed and the error cases are those of
ADR-0035; only the name and the two header names change.

## 3. Validation

`id_header` and `signature_header` must be valid HTTP header names (RFC 9110 token) and must
differ, compared case-insensitively. `signature_header` must not be `host`, `authorization`,
`content-length` or `transfer-encoding`. The policy load refuses a binding that breaks a rule,
naming the resource. `zs schema` requires both fields when the scheme is `hmac-body-signature`.

## 4. The old name

The old scheme name is removed from the engine. A policy file that uses it is refused at load
with serde's unknown-variant error, which lists the valid schemes. Each binding that used it
changes one line:

```json
"auth": { "scheme": "hmac-body-signature", "id_header": "va", "signature_header": "signature" }
```

The diagnostic log's scheme code becomes `hmac_body_signature`.

## 5. Security

No new trust boundary. SECURITY §3 ("the agent signs what the client sends") and §7 keep their
rules with the new name. The §7 row for a request without the id header stays one row, so the
matrix keeps 77 rows and its test keeps its number.

## 6. Tests

- The two existing signing vectors pass unchanged in their numbers under the new scheme, with
  `id_header: "va"`, `signature_header: "signature"` and a neutral host.
- A request without the id header is denied, and the upstream sees nothing (the §7 row).
- A client-sent `signature_header` is replaced, not duplicated.
- The policy load refuses a missing field, equal header names, an invalid header name and each
  reserved `signature_header`.
- `zs schema` and the serde parser agree on the new scheme.

## 7. Calls made here

- Both header names are settings. A fixed `signature` output name would keep a vendor's choice
  in the engine.
- No alias for the old name (section 4). An alias in `apps/zs` would put the vendor name in the
  public tree, and a private-only alias would make the shipped `apps/zs` differ from this
  repository, which R6 forbids.
- The secret stays the HMAC key and also ends the signed string, as in ADR-0035. A scheme
  variant without the trailing secret waits for an API that needs it.
