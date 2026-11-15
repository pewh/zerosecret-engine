# Claims correction: the marketing site and two SECURITY rules

Status: accepted 2026-11-15. The owner accepted D1 to D6 as recommended. For D5 the owner removed
the line "Custom policy rules" from the pricing page.

## Problem

[PRODUCT.md](../PRODUCT.md) §7 says: "Marketing copy carries the same scope as this section." The
marketing site does not have that scope today. It shows capabilities that the engine does not
ship, and it repeats two rules of [SECURITY.md](../SECURITY.md) that `zs init` and the `file`
source do not keep.

The document corrections of 2026-11-05 removed the same statements from the owner documents of
both repositories. They did not include the site, because no rule names the site as a place where
a claim is repeated.

A security engineer who reads the site and then reads the code finds the difference in minutes.
The product asks that reader to trust a binary that terminates TLS. One false statement costs
more trust than the statement is worth.

## Goals

- Each statement on the site is true of the pinned engine release.
- SECURITY §2 and §4 are true of `zs init` and of the `file` source.
- A later claim change has a written rule that names the site.

## Non-goals

- No code change in the engine. A claim that needs code to become true gets its own spec.
- No change to the tiers or the prices. The site owns those.
- No new claim. This spec only narrows or labels.
- Revocation wording. The security-review plan of 2026-11-15 owns it.

## Approaches

| Approach | What it does | Cost | Trade-off |
|---|---|---|---|
| A. Narrow the text (recommended) | Change each statement to what the engine ships. Label the rest "Planned" | About half a day | The site promises less. Every statement survives a code review |
| B. Make the claims true in code | Build five provider adapters, exchange, and a credential store that is not a file | Months | The claims stay. The site stays false until the last one ships |
| C. Remove the sections | Delete the integrations section, the handling rules and the defended list from the site | About one hour | No false statement, but the security page loses its purpose |

A is recommended. B is the product roadmap, not a correction. C removes true statements with the
false ones.

## Corrections

Site paths are relative to `templates/` in the `zerosecret-site` repository. Line numbers are
those of its `main` on 2026-11-15; confirm each before an edit.

### Engine documents

Make each change in `docs/SECURITY.md` here and in the commercial copy (AGENTS.md "Docs and
decisions").

| Id | Where | Text now | Proposed text | Evidence |
|---|---|---|---|---|
| E1 | `docs/SECURITY.md:483` (§4 rule 4) | "No credential value is written to disk. Ever." | "The agent never writes a credential value to disk. Ever. [the rest of the rule stays]. One exception is outside the agent: a `file` source reads its value from a file under `~/.zs-credentials/`, and `zs init` writes that file (0600) and a backup of `.env` under `~/.zs-backups/` (0600). These files are the standing credential of a `file` source; §3 gives the limit." | `README.md:206` |
| E2 | `docs/SECURITY.md:62-63` (§2) | "A coding agent reading credentials out of its own environment, process memory, or the files it can access." | "A coding agent reading credentials out of its own environment, its process memory, or the files of the workspace. A `file` source keeps the value in the developer's home directory, where a process of the same user can read it (§3)." | `docs/SECURITY.md:96-111` |
| E3 | `docs/SECURITY.md:64` (§2) | "A developer keeping a working production credential after leaving the team." | "A developer keeping access through ZeroSecret after leaving the team: a removed member or a revoked device gets no new grant. A static credential that the developer's user could read stays valid until its owner rotates it (§3)." | `docs/SECURITY.md:106-111`; exchange is not implemented (`docs/ARCHITECTURE.md:555`) |

### Site: capabilities that do not ship

| Id | Where | Text now | Proposed text | Evidence |
|---|---|---|---|---|
| S1 | `partials/home/integrations.html:6-10` | HashiCorp Vault, OpenBao, AWS Secrets Manager, GCP Secret Manager and 1Password with no badge | Add "AWS SSM Parameter Store" with no badge as the first entry. Give the five others the "Planned" badge that Azure Key Vault has | PRODUCT §6: "today a source is a file or AWS SSM" |
| S2 | `pages/docs.html:74`, `pages/developers.html:136` | `analytics-db ... postgres L3 exchange strict` | `analytics-db ... postgres L3 retrieve strict` | `docs/ARCHITECTURE.md:85-86`: the agent refuses exchange |
| S3 | `pages/how-it-works.html:151-157` | Retrieve: "Pull stored credential from vault". Exchange: "Preferred" | Retrieve: "Read the stored credential from the configured source (a file or AWS SSM)". Exchange: add the "Planned" badge | The same |
| S4 | `pages/how-it-works.html:183` | "retrieve or exchange → credential" | "retrieve → credential" | The same |
| S5 | `pages/pricing.html:42` | "HTTPS + PostgreSQL" | "HTTPS, PostgreSQL, MySQL, MongoDB, Redis" | `README.md:37-38` |
| S6 | `pages/pricing.html:116` | "Audit export (SIEM)" | "Audit export (NDJSON)" | ROADMAP v2 lists SIEM export as not started |
| S7 | `partials/home/use-cases.html:18-24`, `partials/home/architecture-overview.html:26` | "CI pipelines", "Internal services ... based on workload identity", "CI Runner" | Add the "Planned" badge to the two use cases. Remove "CI Runner" from the workload list | `docs/SECURITY.md:169` (the workload is a declared label) and `:1072` (the CI identity model is deferred to v2) |
| S8 | `partials/home/comparison-table.html:20`, `:26` | "Integrates with existing", "Inherits from provider" | "File or AWS SSM today; vault adapters planned", "Inherits from the source" | PRODUCT §6 |

### Site: statements wider than the security model

| Id | Where | Text now | Proposed text | Evidence |
|---|---|---|---|---|
| S9 | `pages/security.html:136` | "No credential value is written to disk. Ever." | The first two sentences of E1, then: "A `file` source keeps its value in a 0600 file in the developer's home directory." | E1 |
| S10 | `pages/security.html:75` | "A coding agent reading credentials from its environment, memory, or files" | "A coding agent reading credentials from its environment, its memory, or the files of the workspace" | E2 |
| S11 | `pages/security.html:79` | "A developer keeping working production credentials after leaving the team" | "A developer keeping access through ZeroSecret after leaving the team. A static credential still needs rotation" | E3 |
| S12 | `pages/security.html:133` | "...only for the life of one protocol exchange." | Add: "One exception: a value from AWS SSM stays in agent memory for the life of its grant, at most 300 seconds." | `docs/SECURITY.md:471-477` (ADR-0041) |
| S13 | `pages/security.html:271` | "providing auditors with mathematical proof that workloads never held credentials" | "giving auditors evidence for an access-control review: on an intercepted path the workload never holds the upstream credential, and the audit record shows each decision without the value" | PRODUCT §6, last row: "not a proof and not a compliance certification" |
| S14 | `pages/agents.html:80-81`, `partials/home/agent-section.html:24` | "Complete audit trail ... recorded for every access. You know exactly what the agent did." and "Every request is audited" | "Audit trail for every brokered request ... recorded for every access through ZeroSecret." and "Every brokered request is audited" | PRODUCT §7 lists "Every action in every stack is checked and logged" as unsafe |

### The rule that names the site

| Id | Where | Change |
|---|---|---|
| R1 | `AGENTS.md`, "Docs and decisions", after the line about the five owner documents | Add: "The marketing site repeats PRODUCT §7 and the lists of protocols, sources and materialization modes. A change to one of these is also made in the `zerosecret-site` repository." |
| R2 | `README.md` of the site, section "Relationship to ZeroSecret" | Add: "PRODUCT.md §7 of the engine owns the scope of every claim on this site. A capability that the pinned engine release does not ship has a "Planned" or "Future" badge." |

## Decisions for the owner

| Id | Question | Recommendation |
|---|---|---|
| D1 | Approach A, B or C? | A |
| D2 | E1 narrows SECURITY §4 rule 4. AGENTS.md hard rule 5 forbids a weaker claim "to make a test pass". Is a narrower rule that matches the shipped `zs init` permitted? | Yes. The rule is false today; no test is involved. The alternative is a spec that moves the `file` source into the native credential store |
| D3 | E3 and S11 remove the "departed developer" defence for static credentials. Keep it only as "access through ZeroSecret"? | Yes, until exchange ships |
| D4 | S7 labels the CI and internal-service use cases "Planned". Does a tested CI path exist that this spec did not find? | Label them, unless the owner names the test |
| D5 | `pages/pricing.html:124` says "Custom policy rules". The repositories do not say what this is | The owner states what it is, or removes the line |
| D6 | A mechanical check (the site build compares its claim block with PRODUCT §7) in place of R1 and R2? | Not now. Two rules are the smallest change. Add the check when a claim drifts a second time |

## Not verified

The repositories cannot confirm these statements. The owner confirms each or labels it.

- The site names Okta, Microsoft Entra, Google Workspace and Auth0. The test suites use Keycloak.
- The site and `docs/SECURITY.md:919` say "Grant signature invalid: Deny. Alert". This spec found
  no alert mechanism; it did not search the control plane.
- The free tier lists "SSO via any OIDC provider". SSO needs a control plane; local mode has none.
- The explainer video narration was not compared with this list.

## Verification

1. `grep -rn 'mathematical proof\|written to disk. Ever\|exchange  strict' templates/` in the site
   returns nothing.
2. `make build` in the site passes, and each of the five providers of S1 shows a "Planned" badge
   on the built home page.
3. `diff` of `docs/SECURITY.md` between the two repositories shows no new difference in §2 or §4.
4. `tools/public-gates.sh` passes in the engine.
