# Agentic-Friendly `zs` CLI: Schema, Init, and Agent Instructions

- **Status:** Draft / Proposed
- **Date:** 2026-10-22
- **Author:** ZeroSecret Engineering
- **Target Release:** v1
- **Follows:** ADR-0036, ADR-0037, ADR-0038
- **Enforces:** PRODUCT.md §7 (Invariant & Security Claims), SECURITY.md §2, AGENTS.md

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

---

## 1. Intent

Today, integrating ZeroSecret into an application repository requires a human developer or an AI coding agent (Claude Code, Gemini, Cursor, Copilot) to manually construct `zs-policy.json`.

This approach has three failure modes:
1. **Schema Drift & Hallucination:** Agents construct `zs-policy.json` from training data or README examples. If a field name is misremembered (e.g., `auth_type` instead of `auth.scheme`, `target` instead of `host`), `zs run` halts at startup.
2. **Friction in Secret Elimination:** Converting an application with 10 database and API credentials in `.env` into `zs-policy.json` is tedious and error-prone. Developers often miss stripping secrets or leave orphan credentials behind.
3. **Fragile Plaintext Parsing:** Tooling and subagents cannot easily parse `zs doctor` or `zs status` output because the commands emit human-oriented tabular text rather than structured data.

This specification makes the `zs` CLI self-describing and agentic-friendly through four commands:
- `zs schema`: Outputs the canonical JSON Schema for `zs-policy.json` matching the compiled binary.
- `zs init`: Scans application files (`.env`, `docker-compose.yml`), detects external APIs and databases, safely generates a starter `zs-policy.json`, and outputs clean placeholders without exposing credentials.
- `zs agent-instructions`: Emits a concise, version-pinned markdown prompt that developers can pipe directly to AI coding agents.
- `zs doctor --json`: Emits machine-readable diagnostics for automated checks.

---

## 2. Goals, Non-Goals, and Anti-Goals

### Goals
1. **Version-Accurate Self-Description:** Any AI agent can run `zs schema` to get the exact JSON Schema for the installed binary's policy parser.
2. **Automated Policy Scaffolding:** `zs init` inspects local config files non-destructively and produces a starter `zs-policy.json` with detected resource bindings.
3. **Hard Credential Redaction:** In accordance with Hard Rule 4, `zs init` and `zs schema` NEVER echo, log, or leak a credential value. Detected secrets are replaced with `<REDACTED_BY_ZEROSECRET>`.
4. **Machine-Readable Diagnostics:** `zs doctor --json` and `zs status --json` output structured JSON for programmatic validation.
5. **Simpler Onboarding Prompt:** The integration instructions in `README.md` reduce to three commands:
   ```bash
   zs agent-instructions | pbcopy  # or paste to AI agent
   ```

### Non-Goals
1. **Automating Cloud Control Plane Setup:** `zs init` creates local policy bindings. Creating organizations, issuing grants, or configuring remote Vault/AWS secrets managers remains an operator action via the dashboard or seed file.
2. **Replacing Manual Policy Tuning:** Advanced schemes (custom AWS SigV4 path regexes, a payment gateway's signatures, complex WebSocket filters) still permit manual authoring.
3. **Network Discovery:** `zs init` does not scan live external networks or probe ports. It reads only committed or local configuration files in the workspace.

### Anti-Goals
1. **No Silent File Overwrites:** `zs init` will never overwrite an existing `zs-policy.json` without an explicit `--force` flag.
2. **No Secret Transmission:** `zs init` operates 100% offline. No local environment data is sent to the control plane or any remote server.

---

## 3. Command Specifications

### 3.1 `zs schema`
Prints the JSON Schema (draft 2020-12) for `zs-policy.json` to `stdout`.

```bash
zs schema
```

#### Output
A valid JSON Schema defining:
- `run` object: `control`, `control_ca`, `credentials_dir`, `ca_dir`, `audit`.
- `bindings` array:
  - `resource`: string, required.
  - `host`: string, required.
  - `protocol`: enum (`https`, `http`, `postgres`, `mysql`, `mongo`), default `https`.
  - `auth`: object with `scheme` enum (`bearer`, `basic`, `api-key-header`, `query-param`, `aws-sigv4`, `hmac-body-signature`, `websocket-json-field`).
  - `listen_port`: integer (optional).
  - `local_endpoint`: boolean (optional).
  - `upstream_host`, `upstream_port`, `upstream_ca`, `upstream_cert_sha256`, `upstream_plaintext`.
- `grants`: cached offline grant array.

Exit code: `0` on success.

---

### 3.2 `zs init`
Scans the current directory for credential configurations, scaffolds `zs-policy.json`, backs up the original environment file, and sanitizes `.env` directly in place.

```bash
zs init [--dry-run] [--force] [--from-env <path>] [--control <url>] [--listen-port-start <port>]
```

#### Flags
| Flag | Description | Default |
|---|---|---|
| `--dry-run` | Previews the generated `zs-policy.json` and the `.env` diff to `stdout` without writing or modifying any files. | `false` |
| `--force` | Overwrites `zs-policy.json` if it already exists. | `false` |
| `--from-env <path>` | Specifies the target environment file to scan and sanitize. | `.env` (falls back to `.env.local`, `.env.development`) |
| `--control <url>` | Sets the control plane URL in the `run` block. | `http://127.0.0.1:8443` |
| `--listen-port-start <port>` | Starting loopback port for generated L3 database listeners. | `54320` |

#### In-Place Modification & Backup Strategy
1. **Pre-modification Backup:**
   Before modifying `.env`, `zs init` copies the exact existing file to:
   `.env.zerosecret_backup_<YYYYMMDD_HHMMSS>`
2. **Strict File Permissions:**
   The backup file is created with permissions `0600` (readable and writable only by the current user).
3. **Automatic `.gitignore` Protection:**
   Because the backup file contains real credentials, `zs init` inspects `.gitignore` in the repository root. If `.gitignore` does not already ignore `*.zerosecret_backup_*`, `zs init` automatically appends:
   ```text
   # ZeroSecret pre-init credential backups
   *.zerosecret_backup_*
   ```
   This eliminates the risk of an accidental `git add .` committing real secrets.
4. **Direct In-Place Sanitization of `.env`:**
   `zs init` rewrites `.env` in place:
   - **HTTP API Keys (e.g. `STRIPE_SECRET_KEY`, `OPENAI_API_KEY`):** Replaces the real secret with a placeholder token: `placeholder_managed_by_zerosecret`. This satisfies framework validation (e.g. non-empty string checks) while ensuring no real secret remains in `.env`.
   - **Database Connection Strings (`DATABASE_URL`, `MONGO_URI`):** Rewrites connection strings to point to the local ZeroSecret listener (e.g. `postgres://app@127.0.0.1:54320/mydb`), stripping out passwords and remote hosts.

#### Detection & Transformation Heuristics
`zs init` parses key-value pairs from target files and applies zero-knowledge classification:

| Pattern in Key or Value | Detected Resource | Protocol | Auth Scheme | Generated Binding & Rewritten `.env` |
|---|---|---|---|---|
| `STRIPE_.*KEY`, `sk_live_.*`, `sk_test_.*` | `stripe` | `https` | `bearer` | Binding host: `api.stripe.com`<br/>`.env`: `STRIPE_SECRET_KEY=placeholder_managed_by_zerosecret` |
| `OPENAI_API_KEY`, `sk-proj-.*` | `openai` | `https` | `bearer` | Binding host: `api.openai.com`<br/>`.env`: `OPENAI_API_KEY=placeholder_managed_by_zerosecret` |
| `GITHUB_TOKEN`, `ghp_.*` | `github` | `https` | `bearer` | Binding host: `api.github.com`<br/>`.env`: `GITHUB_TOKEN=placeholder_managed_by_zerosecret` |
| `postgres://.*:.*@(?P<host>[^:/]+):(?P<port>\d+)?/(?P<db>.*)` | `postgres-db` | `postgres` | brokered | Binding: host=`<host>`, listen_port=`54320`<br/>`.env`: `DATABASE_URL=postgres://127.0.0.1:54320/<db>` |
| `mysql://.*:.*@(?P<host>[^:/]+):(?P<port>\d+)?/(?P<db>.*)` | `mysql-db` | `mysql` | brokered | Binding: host=`<host>`, listen_port=`33060`<br/>`.env`: `DATABASE_URL=mysql://127.0.0.1:33060/<db>` |
| `mongodb://.*@(?P<host>[^:/]+):(?P<port>\d+)?/(?P<db>.*)` | `mongo-db` | `mongo` | brokered | Binding: host=`<host>`, user=`app`, listen_port=`27018`<br/>`.env`: `MONGO_URI=mongodb://127.0.0.1:27018/<db>` |

#### Safety & Rollback Instructions
If a developer needs to revert changes made by `zs init`:
```bash
cp .env.zerosecret_backup_<timestamp> .env
rm zs-policy.json
```

Exit codes:
- `0`: Scaffolding succeeded.
- `1`: Target `zs-policy.json` already exists (and `--force` was not passed).
- `2`: Invalid argument.

---

### 3.3 `zs agent-instructions`
Emits an authoritative system prompt tailored to the installed version of `zs`.

```bash
zs agent-instructions [--markdown]
```

#### Output
A concise markdown block designed to be ingested into an AI agent's prompt context:

````markdown
# ZeroSecret Integration Protocol (CLI v[VERSION])

You are integrating ZeroSecret into this application repository.
Rule 1: The application must possess ZERO secrets in .env, files, or memory.
Rule 2: Never print or log credential values.

Procedure:
1. Verify Environment:
   Run `zs status` to check device enrolment.
   If unenrolled, instruct developer to run `zs login`.
2. Inspect Schema:
   Run `zs schema` to get the exact JSON schema for `zs-policy.json`.
3. Scaffold Policy:
   Run `zs init --dry-run` to preview detected external bindings.
   Write `zs-policy.json` matching detected services.
4. Clean Project:
   Replace real secrets in `.env` with empty values.
5. Wrap Execution:
   Prefix startup commands with `zs run -- <command>`.
6. Validate:
   Run `zs doctor` and test application health.
````

---

### 3.4 `zs doctor --json` and `zs status --json`
Provides structured JSON output for tool consumption.

#### `zs doctor --json` Output
```json
{
  "status": "ok",
  "policy_file": "zs-policy.json",
  "policy_valid": true,
  "bindings_count": 3,
  "ca_status": "valid",
  "ca_storage": "macos-keychain",
  "diagnostics": []
}
```

#### `zs status --json` Output
```json
{
  "enrolled": true,
  "device_id": "dev-c7646bad3a980603260b366052fa9ee0",
  "subject": "dev-alice",
  "control_url": "https://control.internal.example:8443",
  "ttl_remaining_seconds": 583200,
  "resources_count": 3,
  "cached_grants_count": 3
}
```

---

## 4. Architectural Boundaries & Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor Agent as Coding Agent / CLI
    participant ZS as apps/zs binary
    participant Disk as Local Files (.env, compose)
    participant Policy as zs-policy.json

    alt Schema Inspection
        Agent->>ZS: zs schema
        ZS-->>Agent: JSON Schema (draft 2020-12)
    end

    alt Policy Scaffolding
        Agent->>ZS: zs init --from-env .env
        ZS->>Disk: Read .env (read-only)
        Note over ZS: Parse hosts & protocols;<br/>SCRUB secret values from memory
        ZS->>Disk: Write .env.zerosecret_backup_<timestamp> (chmod 0600)
        ZS->>Disk: Ensure *.zerosecret_backup_* in .gitignore
        ZS->>Policy: Write zs-policy.json (0644)
        ZS->>Disk: Rewrite .env in place with placeholder tokens
        ZS-->>Agent: Summary report (Hosts detected, 0 secrets stored)
    end

    alt Machine Diagnostics
        Agent->>ZS: zs doctor --json
        ZS-->>Agent: {"status": "ok", "policy_valid": true}
    end
```

---

## 5. Security Invariants & Fail-Closed Behavior

1. **Credential Non-Retention:** The scanner in `zs init` parses values using local memory buffers that are overwritten/dropped immediately after regex classification. Credential strings never reach logs, stdout, or policy files.
2. **Deterministic Fail-Closed:** If an environment file contains malformed syntax, `zs init` halts with an error and does not generate a partial, insecure policy.
3. **No Overwrite Hazard:** If `zs-policy.json` already exists and `--force` is omitted, the CLI immediately halts with:
   `zs: zs-policy.json already exists; pass --force to overwrite`.

---

## 6. Implementation Plan & Tasks

1. **Task 1: `zs schema` implementation:** Add schema generation reflecting `zs::AgentFile` and `zs::ResourceBinding` in `apps/zs/src/schema.rs`.
2. **Task 2: `zs agent-instructions` implementation:** Add embedded markdown template generator in `apps/zs/src/instructions.rs`.
3. **Task 3: `zs doctor --json` & `zs status --json`:** Add JSON serialization flags to `main.rs`, `doctor`, and `status`.
4. **Task 4: `zs init` scanner:** Add `.env` detection and sanitized template generation in `apps/zs/src/init.rs`.
5. **Task 5: Verification & Acceptance Tests:** Unit tests in `apps/zs/tests/` asserting that `zs init` redacts secrets and generates valid `zs-policy.json` accepted by `zs doctor`.

