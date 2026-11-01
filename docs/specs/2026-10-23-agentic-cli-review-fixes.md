# Agentic CLI: Review Fixes

- **Status:** Accepted (owner request, 2026-10-23)
- **Date:** 2026-10-23
- **Amends:** [2026-10-22-agentic-cli.md](2026-10-22-agentic-cli.md). Where the two disagree, this spec wins.
- **Plan:** the agentic CLI plan (not published), Task 7
- **Enforces:** AGENTS.md Hard Rules 3 and 4

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

---

## 1. Why

A review of commit `eef43ec2` found defects that break the security invariant, and gaps between the
spec, the plan and the code. A spec is immutable once written, so this file records the decisions
that replace the conflicting parts of the 2026-10-22 spec.

| # | Defect in `eef43ec2` | Effect |
|---|---|---|
| 1 | Backup name has one-second resolution and the file is truncated on open | `zs init` then `zs init --force` in the same second replaced the only backup with the sanitized file. The original credentials were lost |
| 2 | Database URL split on the first `@` | Part of a password that contains `@` was written to the binding `host` in `zs-policy.json`, a committed file |
| 3 | Query string copied unchanged | `?password=...` stayed in `.env` |
| 4 | A second run read the sanitized `.env` | The new binding pointed the broker at its own listener (`127.0.0.1:54320`) |
| 5 | Catch-all on `SECRET`, `TOKEN`, `PASSWORD`, `_KEY` | App-owned secrets such as `JWT_SECRET` became the public constant `placeholder_managed_by_zerosecret`. Public keys (`pk_live_`) were also removed. Nothing reported which keys changed |
| 6 | Hand-written `zs schema` | No `additionalProperties: false`, so `auth_type` passed the schema but failed the parser. `bindings` not required. `grants`, `signing_keys`, `client_auth_plugin` missing |
| 7 | `doctor --json` | `diagnostics` was always empty. The policy error was dropped |
| 8 | `status --json` | `enrolled` showed the session file, not device enrolment. Exit 0 when signed out |

## 2. Decisions

### 2.1 `zs init` scanner

1. **URL parsing.** The user info ends at the last `@` before the query string. A host that is
   empty, contains `,`, a space or `@`, or has a port outside 1-65535 is not parsed. The key is
   reported as not brokered.
2. **Query parameters.** A parameter whose name contains `password`, `passwd`, `pwd`, `secret` or
   `token` is removed from the rewritten URL. Other parameters stay.
3. **Rewritten URL.** The original scheme stays (`postgresql://` stays `postgresql://`). Postgres and
   MySQL URLs keep the user name: `postgres://<user>@127.0.0.1:<listen_port>/<db>`. Mongo URLs drop
   the user, because the binding carries it: `mongodb://127.0.0.1:<listen_port>/<db>`. A Mongo
   `authSource` query parameter also sets the binding `auth_source`.
4. **Listen ports.** One counter for all database bindings. It starts at `--listen-port-start`
   (default `54320`, range 1-65535) and increases by one for each binding in file order. This
   replaces the fixed per-protocol ports (`33060`, `27018`) in the 2026-10-22 heuristics table. If
   the counter passes 65535, `zs init` stops and writes nothing.
5. **Loopback URLs.** A database URL to `localhost` or a loopback address without a password holds
   no credential. `zs init` leaves the line unchanged and creates no binding.
6. **Not brokered.** `zs init` replaces only values that it binds: Stripe, OpenAI, GitHub and the
   database URLs above. It does not change other secret-looking values. It lists their key names,
   never their values, as `not brokered, left in <file>: <KEY> (<reason>)`. This covers:
   - key names that contain `SECRET`, `PASSWORD`, `PASSWD`, `TOKEN`, `API_KEY`, `PRIVATE_KEY`,
     `CREDENTIAL` or end in `_KEY`;
   - URLs with an embedded password for other protocols (for example `redis://`);
   - `mongodb+srv://` URLs, because the Mongo broker does not do DNS SRV lookups;
   - Stripe webhook secrets (`whsec_`).
7. **Public values.** Key names that contain `PUBLIC` or `PUBLISHABLE`, and values that start with
   `pk_live_` or `pk_test_`, are not secrets. `zs init` does not change or report them.
8. **Malformed input (spec 5.2).** A line that is not blank, not a comment and has no `=`, an empty
   key, or a quoted value without a closing quote on the same line stops `zs init` with exit 2. The
   error names the line number only, never the content. No file is written.
9. **`export` prefix and inline comments.** `export KEY=value` is accepted and kept. For an unquoted
   value, text after ` #` is a comment.

### 2.2 `zs init` files

1. **Backup.** The backup is created with `create_new` and mode `0600`, and synced to disk before
   `.env` changes. If `<file>.zerosecret_backup_<UTC timestamp>` exists, `zs init` uses `_1`, `_2`
   and so on up to `_99`. It never overwrites a backup.
2. **Sanitized marker.** When `zs init` replaces at least one value, the first line of the rewritten
   file is:
   `# zs init: brokered secrets in this file were replaced; the original is in a .zerosecret_backup_* file`
3. **No second run.** If the file has the marker line or contains `placeholder_managed_by_zerosecret`,
   `zs init` stops with exit 1 and tells the user to restore the backup first. `--force` does not
   change this. `--force` only allows `zs-policy.json` to be overwritten.
4. **Nothing to replace.** If no value is replaced, `zs init` writes `zs-policy.json` only. It
   creates no backup and does not change `.env` or `.gitignore`.
5. **Dry run.** `--dry-run` writes nothing, so it runs even if `zs-policy.json` exists.
6. **No env file.** If no `--from-env` is given and `.env`, `.env.local` and `.env.development` are all
   missing, `zs init` stops with exit 2.

Exit codes for `zs init`: `0` done; `1` refused (`zs-policy.json` exists without `--force`, or the
env file is already sanitized); `2` invalid argument, missing, unreadable or malformed env file, or
a write error.

### 2.3 `zs schema`

The schema must accept exactly what the parser accepts, as far as JSON Schema can say it:

- root `required: ["bindings"]`; `run`, `bindings`, `signing_keys` and `grants` described;
- `additionalProperties: false` on `run` and on each binding, as `#[serde(deny_unknown_fields)]` does;
- `client_auth_plugin` with its two values; `listen_port` 1-65535;
- each `auth.scheme` with its required fields (`if`/`then`).

A test compares the schema with the parser. It reads the field list from the serde
`unknown field` error for `ResourceBinding` and `RunSettings`, and the variant list from the
`unknown variant` error for `HttpAuth`. A field added to the parser without a schema change fails
the test.

### 2.4 `zs doctor --json`

Replaces spec 3.4:

```json
{
  "status": "ok",
  "policy_file": "zs-policy.json",
  "policy_valid": true,
  "bindings_count": 3,
  "signing_keys_count": 1,
  "cached_grants_count": 3,
  "ca_dir": ".zs-ca",
  "ca_certificate_present": true,
  "audit_path": ".zs-audit/audit.jsonl",
  "diagnostics": [
    { "level": "error", "check": "policy", "message": "policy: unknown field `auth_type`, ..." }
  ]
}
```

- `status` is `"error"` and the exit code is 1 when the policy does not load. Otherwise `status` is
  `"ok"` and the exit code is 0.
- A missing `ca.crt` is an `info` diagnostic. It does not change `status`.
- `ca_storage` and `ca_status: "valid"` are removed. `doctor` only checks that the file exists, so
  "valid" claimed more than it checked.

### 2.5 `zs status --json`

Replaces spec 3.4:

```json
{
  "signed_in": true,
  "subject": "dev-alice",
  "enrolled": true,
  "device_id": "dev-c7646bad3a980603260b366052fa9ee0",
  "control_url": "https://control.internal.example:8443",
  "resources_count": 3,
  "cached_grants_count": 3,
  "error": null
}
```

- `enrolled` and `device_id` come from the device record for `control_url`, as in the text output.
- `error` holds the device-record error line, if any.
- Exit code matches the text output: 1 when signed out or when the device record cannot be read.
- `ttl_remaining_seconds` is removed. The device record has no expiry to report.

### 2.6 Flags

- `--json` is accepted only by `status` and `doctor`. Other commands refuse it with exit 2.
- `zs schema` and `zs agent-instructions` take no arguments. The `--markdown` flag in spec 3.3 is
  removed, because the output is always markdown.

### 2.7 `zs agent-instructions`

- The header is `# ZeroSecret Integration Protocol (zs <version>)`, using the crate version.
- Step 4 of spec 3.3 ("Replace real secrets in `.env` with empty values") is replaced: the agent
  runs `zs init`, and asks the developer about each key listed as not brokered. It never copies a
  value.
- The validation step uses `zs doctor --json` and checks `status`.
