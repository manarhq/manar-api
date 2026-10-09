# Policy model (Phase 6: Policy & Risk Engine)

This is `manar-api`'s implementation of Sections 21-26 of the master
prompt: `docs/superpowers/specs/2026-08-18-phase6-policy-risk-design.md`.
It covers the declarative rule-content format, the versioning model, and
the deterministic `PolicyEngine`/`RiskEngine` layered on top of Phase 5's
OpenFGA task-scope check (`docs/authorization-model.md`).

## Relationship to Phase 5 (OpenFGA) — read this first

Phase 5's OpenFGA `check()` already decides **whether an action is
permitted at all** for a given task/tool/action/resource. This phase's
`PolicyEngine` does **not** re-decide that. It adds _extra, org-defined
restrictions on top of_ an already-permitted action — e.g. "endpoint
isolation is task-grantable, but it always requires human approval
regardless." Consequently:

- If no policy rule matches a request OpenFGA already allowed, the policy
  engine's effect is `ALLOW` (pass-through) — a normal, fully evaluated
  outcome, not a "trustworthy decision" failure.
- Fail-closed (Section 22) applies to genuine failures: can't load
  policies, a DB error, malformed stored content. Those `DENY`. "No rule
  matched" is never conflated with "couldn't evaluate."

## Data model

- **`Policy`** (`prisma/tenant.prisma`): `id`, `name` (unique per tenant
  database), `description`, `createdAt`. Carries no rule content itself —
  see `PolicyVersion`.
- **`PolicyVersion`**: `id`, `policyId`, `version` (monotonic int, unique
  per `policyId`), `status` (`DRAFT | PUBLISHED`), `content` (the rule set,
  see below), `contentHash`, `authorId` (`UserProfile` FK), `reason`,
  `previousVersionId` (nullable self-FK — the chain predecessor, see
  below), `publishedAt` (nullable), `createdAt`.

"The policy's current content" always means **the latest `PUBLISHED`
`PolicyVersion` for that `Policy`** — resolved live, on every
`PolicyEngine.evaluate` call, never cached across requests this phase.

**Published versions are never mutated or deleted.** There is no
update/delete endpoint for one at all (see
`src/policy/policy.controller.ts`). Editing a published policy always
means creating a new `DRAFT` version (`version` n+1) via `POST
/policies/:id/versions`, then publishing it. A rollback is likewise a
_new_ version whose `content` happens to match an older version's — never
an in-place revert — with `reason` explicitly recording that it's a
rollback (e.g. `"Rollback to version 1"`).

### `previousVersionId` is a chain, not a "rolled back from" pointer

`previousVersionId` always points at whichever version was the latest one
(`DRAFT` or `PUBLISHED`) for this policy at the moment this version was
created — the immediate chain predecessor — **even for a rollback**, whose
`content` is copied from some older, not-necessarily-immediate version.
Example:

```
v1 (published) --previousVersionId--> null
v2 (published) --previousVersionId--> v1
v3 (published, content == v1's content, reason "Rollback to version 1")
   --previousVersionId--> v2
```

`v1` and `v2` remain unchanged and individually readable
(`GET /policies/:id/versions/:versionId`) after the rollback — the chain
stays linear and every version is still reachable, which is what makes the
full history auditable end to end regardless of how many rollbacks occur.

## Rule content schema

`src/policy/policy-content.schema.ts`'s `PolicyContentSchema` (Zod) is the
single source of truth, enforced identically whether a caller submits JSON
or YAML (see "YAML⇄JSON round-trip" below):

```ts
{
  rules: [
    {
      name?: string,              // human-readable label, never matched against
      toolId: string,             // exact match, or "*" ("any tool")
      actionId: string,           // exact match, or "*" ("any action")
      resourcePattern?: string,   // exact match, "*" (default, "any resource"), or a prefix ending in "*"
      effect: "ALLOW" | "DENY" | "REQUIRE_APPROVAL",
      riskWeight?: number,        // 0-100, additive RiskEngine contribution when this rule matches
      riskFloor?: number,         // 0-100, RiskEngine score is clamped up to at least this when this rule matches
      description?: string,       // free-text rationale, never evaluated
    },
    // ...
  ]
}
```

- **Matching**: a rule matches a request `{ toolId, actionId, resource }`
  iff `toolId` is `"*"` or equals the request's `toolId`, **and**
  `actionId` is `"*"` or equals the request's `actionId`, **and**
  `resourcePattern` is `"*"`, equals the request's `resource`, or ends in
  `*` and the resource starts with what comes before it (`manar/demo-repo:*`
  matches every branch of that project; ADR-0011). Prefix patterns exist in
  policy only: task `allowedResourceSelectors[].pattern` stays exact or
  `"*"` (`docs/authorization-model.md`), because those become OpenFGA tuples.
- **First-match-wins**: rules are evaluated in array order; the first
  matching rule determines this policy's effect for the request. A policy
  with no matching rule contributes nothing (pass-through — see the note
  above).
- **`riskWeight`/`riskFloor`** feed `RiskEngine.score` (see below) — a
  policy rule with neither contributes no risk signal beyond
  `RiskEngine`'s other inputs.

## `PolicyEngine`

`src/policy/policy-engine.service.ts`. `evaluate(tenantClient, tenantId,
{ toolId, actionId, resource })`:

1. Loads every `PUBLISHED` `PolicyVersion` for the tenant, one per
   `Policy` (the highest `version` among that policy's `PUBLISHED` rows —
   never a `DRAFT`).
2. Validates and evaluates each policy's `content` against the request
   (first-match-wins, per above).
3. Combines every policy's own effect **most-restrictive-wins**:
   `DENY` &gt; `REQUIRE_APPROVAL` &gt; `ALLOW`, across _all_ policies —
   e.g. one policy says `ALLOW` and a second says `DENY` for the same
   request → overall `DENY`.
4. No policy at all, or no policy's rules match → `ALLOW` (pass-through —
   this is the normal, expected outcome for the overwhelming majority of
   requests, not a fallback).
5. Any failure loading a policy from the database, or any stored
   `content` that fails `PolicyContentSchema` validation → the _entire_
   evaluation fails closed to `DENY`, logged clearly. This is the actual
   fail-closed case (Section 22) — never conflated with "no rule matched."

## `RiskEngine`

`src/risk/risk-engine.service.ts`. `score(tenantClient, { toolId,
actionId, resource, task, policyMatch }) → { deterministicRiskScore,
aiAdvisoryScore: null, finalRiskScore, reasonCodes[] }`, 0-100.
`finalRiskScore` equals `deterministicRiskScore` this phase — AI advisory
scoring is Phase 10, the field exists and stays `null` until then.

This phase's inputs are necessarily limited — there is no Tool Registry
yet (Phase 7, which will add `ToolAction.riskBaseScore`/`mutating`/
`destructive` as a _real_ input; this phase does not fake one). The
deterministic contributors available now, each recorded as a
`reasonCodes` entry:

- **Baseline** (`baseline_risk`): always contributes 10 — "nothing is
  risk-free," not a fallback-to-zero.
- **Delegation depth** (`delegation_depth:<n>`): the task's ancestor-chain
  length (reusing `TasksService.getAncestorChain` — Phase 5's own
  chain-walking logic, not re-derived), contributing `min(depth * 5, 30)`
  — deeper delegation, marginally higher baseline risk.
- **Real per-action risk metadata** (`tool_action_risk_base:<n>`,
  `tool_action_mutating:<n>`, `tool_action_destructive:<n>`): **superseded
  by Phase 7b** — the crude, explicitly-temporary destructive-keyword
  heuristic this phase originally shipped (a regex over `actionId` for
  words like `delete`/`isolate`/`terminate`/...) has been deleted
  entirely, replaced by real lookups against a registered
  `ToolAction.riskBaseScore`/`mutating`/`destructive` (Phase 7b's Tool
  Registry — see docs/tool-gateway.md). When `{ toolId, actionId }` has no
  registered `ToolAction` at all, this contributes nothing (never a
  guess) — see `RiskEngine`'s own doc comment.
- **Matched policy rule's own `riskWeight`/`riskFloor`**
  (`policy_risk_weight:<n>` / `policy_risk_floor:<n>`): if the request
  matched a policy rule carrying either, `riskWeight` is added to the sum
  and `riskFloor` clamps the final score up to at least that value.

`deterministicRiskScore` = `clamp(sum of applicable additive
contributors, 0, 100)`, then clamped up to `riskFloor` if the matched
rule set one, then clamped to `[0, 100]` again.

## Wiring into `AuthorizationService`

Inserted into Phase 5's existing pipeline (`src/authorization/authorization.service.ts`)
strictly _after_ the existing OpenFGA `check()` succeeds and _before_ the
existing `executionCount` increment — none of Phase 5's own steps 1-5 are
touched:

1. `PolicyEngine.evaluate(...)`. `DENY` → the whole request `DENY`s
   immediately (`reason: 'policy_denied'`, or `'policy_evaluation_failed'`
   for a genuine load/parse failure — see above).
2. `RiskEngine.score(...)`.
3. `REQUIRE_APPROVAL` if the matched policy effect says so, **or**
   `finalRiskScore > task.riskCeiling` (Phase 5's `riskCeiling` field,
   defined since that phase but unused until now — this phase activates
   it).
4. Otherwise `ALLOW`, and `executionCount` increments exactly as Phase 5
   already did.

`REQUIRE_APPROVAL` is a real, stable response value from this phase
onward (`{ decision: 'REQUIRE_APPROVAL', reason, riskScore }`) — Phase 8
will build the actual approval workflow that lets it eventually resolve to
execution. **This phase implements no path to fulfil a
`REQUIRE_APPROVAL` decision** — it's correctly a dead end for now.

## Policy management endpoints

Human-facing, `JwtAuthGuard`+`RolesGuard`-gated
(`src/policy/policy.controller.ts`), mirroring `TasksController`'s
conventions:

| Endpoint                                         | Role gate                                                 | Purpose                                                                              |
| ------------------------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `POST /policies`                                 | `SECURITY_ADMIN`\|`TENANT_OWNER`\|`AI_GOVERNANCE_MANAGER` | Create a `Policy` + its first `DRAFT` version (JSON `content` or YAML `contentYaml`) |
| `POST /policies/:id/versions`                    | same                                                      | New `DRAFT` version — `content`, `contentYaml`, or `rollbackToVersionId`             |
| `POST /policies/:id/versions/:versionId/publish` | `SECURITY_ADMIN`\|`TENANT_OWNER` only                     | `DRAFT` → `PUBLISHED`                                                                |
| `GET /policies/:id`                              | same as create                                            | Policy + its current (latest `PUBLISHED`) content                                    |
| `GET /policies/:id/versions`                     | same                                                      | Full version history (append-only)                                                   |
| `GET /policies/:id/versions/:versionId`          | same                                                      | One version; `?format=yaml` returns YAML text instead of JSON                        |

No update/delete endpoint for a published version exists anywhere in this
surface — by design, permanently (not "not built yet").

## YAML⇄JSON round-trip

`src/policy/policy-content-codec.ts`, backed by `js-yaml` (v5 — `load()`
is the safe parser by default since v4, no separate "safeLoad" API to
remember). `parsePolicyContentYaml`/`dumpPolicyContentYaml` are the
inverse of each other; `computeContentHash` canonicalizes the JSON
structure (recursively sorts every object's keys; arrays keep their
original order, since order is semantically significant there —
first-match-wins) before hashing, so a hand-written YAML policy and its
JSON equivalent — submitted in either order, with keys in any order —
produce **byte-identical stored intent** and an identical
`PolicyVersion.contentHash`. See
`src/policy/policy-content-codec.spec.ts`.

## Example policies

Illustrative content for this phase's tests — not new infrastructure, and
not shipped as seed data.

### SOC Read Policy

A permissive baseline: SOC operators' tooling may read anything, but nothing
destructive, from the `soc` and `siem` tools. Everything else is
unaffected (pass-through to whatever else already applies).

```yaml
rules:
  - name: Allow SOC/SIEM reads
    toolId: soc
    actionId: read
    effect: ALLOW
  - name: Allow SIEM reads
    toolId: siem
    actionId: read
    effect: ALLOW
  - name: Deny SOC/SIEM deletes
    toolId: soc
    actionId: delete
    effect: DENY
    riskWeight: 40
```

### Endpoint Isolation Approval Policy

Endpoint isolation may be task-grantable via OpenFGA, but this
organization always wants a human in the loop before an agent actually
isolates a host — regardless of what the task itself was authorized to
do.

```yaml
rules:
  - name: Endpoint isolation always requires approval
    toolId: edr
    actionId: isolate_host
    resourcePattern: '*'
    effect: REQUIRE_APPROVAL
    riskWeight: 55
    riskFloor: 60
    description: >
      Isolating a host is disruptive and hard to reverse quickly — always
      route through human approval, even for a task that was otherwise
      granted the edr/isolate_host action.
```

### IAM Restriction Policy

IAM changes are always denied outright for autonomous agents this
organization has not yet decided to trust with identity changes at all —
independent of anything a task's own grants say.

```yaml
rules:
  - name: Deny all IAM mutations
    toolId: iam
    actionId: '*'
    effect: DENY
    riskWeight: 80
    description: Autonomous agents may never mutate IAM state, full stop.
  - name: Allow IAM reads
    toolId: iam
    actionId: read
    effect: ALLOW
```

(Note the ordering: the specific `read` `ALLOW` rule must come _before_
the broad `actionId: "*"` `DENY` rule for `iam` reads to actually be
allowed — first-match-wins means rule order is part of the policy's
actual meaning, not just presentation.)

## Out of scope this phase

- Actual approval workflow/UI/Temporal (Phase 8) — `REQUIRE_APPROVAL` is a
  dead-end response this phase, by design.
- Tool Registry, real per-action risk metadata (Phase 7).
- AI advisory risk scoring (Phase 10) — field exists, stays `null`.
- Kill switches (dedicated later phase).
- Policy GUI editor (Phase 11 — YAML/JSON API only this phase).
