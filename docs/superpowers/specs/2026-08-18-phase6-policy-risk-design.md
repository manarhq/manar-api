# Phase 6: Policy & Risk Engine — Design

Status: Approved (autonomous execution)
Scope: `manar-api` only
Depends on: Phase 5 (`AuthorizationService`/`POST /agent/v1/authorize`,
OpenFGA task-scoped grants)

## Purpose

Implement Sections 21-26: a deterministic, versioned, immutable policy
engine layered on top of Phase 5's OpenFGA task-scope check, plus a
numeric (0-100) risk engine. Both slot into the authorization pipeline
between "OpenFGA authorization" and "final decision" (Section 24). AI
advisory scoring is Phase 10 — this phase's `aiAdvisoryScore` stays null,
`finalRiskScore` equals `deterministicRiskScore`.

**Relationship to OpenFGA (Phase 5) — read this before designing
anything**: OpenFGA/task-scope already establishes _whether the agent is
permitted at all_ for this tool/action/resource. The policy engine does
NOT re-decide that. It adds _extra, org-defined restrictions on top_ of
an already-permitted action — e.g. "endpoint isolation is task-grantable,
but always requires human approval regardless." Consequently: if no
policy rule matches a request that OpenFGA already allowed, the policy
engine's effect is ALLOW (pass-through) — this is a normal, fully
evaluated outcome, not a "trustworthy decision" failure. Fail-closed
(Section 22) applies to actual failures — can't load policies, DB error,
malformed policy content — those DENY. Don't conflate "no rule matched"
with "couldn't evaluate."

## Data model (tenant DB)

- `Policy`: `id`, `name` (unique per tenant), `description`, `createdAt`.
- `PolicyVersion`: `id`, `policyId` (FK), `version` (int, monotonic per
  policy), `status` (enum: `DRAFT | PUBLISHED`), `content` (Json — the
  rule set, see below), `contentHash`, `author` (FK `UserProfile`),
  `reason`, `previousVersionId` (nullable self-FK — the version this was
  derived from, including rollbacks), `publishedAt` (nullable),
  `createdAt`. **Published versions are never mutated or deleted** —
  editing always creates version n+1; rollback creates a new version
  whose `content` matches an older one, `reason` says so explicitly.
  "Current" policy content = the latest `PUBLISHED` version.

Migration.

## Rule content schema

Design a small, real declarative format (not a placeholder) — you decide
the exact shape, but it must support at minimum: matching by
`toolId`/`actionId` (exact or wildcard), an `effect`
(`ALLOW | DENY | REQUIRE_APPROVAL`), first-match-wins ordering within a
policy, and an optional `riskWeight`/`riskFloor` contribution used by the
risk engine below. Document the schema in `docs/policy-model.md` with
examples resembling the product's own demo policies ("SOC Read Policy",
"Endpoint Isolation Approval Policy", "IAM Restriction Policy") — these
are illustrative content for this phase's tests, not new infrastructure.
Provide a YAML ⇄ JSON round-trip utility (Section 21 — GUI/YAML/JSON must
manipulate the same underlying model; there's no GUI yet, but the API
must not be JSON-only) with a test proving a YAML policy and its JSON
equivalent produce identical stored `content`.

## `PolicyEngine`

`evaluate({ tenantId, toolId, actionId, resource }) → { effect, matchedRule?, policyId? }`:
loads every `PUBLISHED` `PolicyVersion` (latest per `Policy`) for the
tenant, evaluates each against the request, combines results
**most-restrictive-wins** (`DENY` beats `REQUIRE_APPROVAL` beats
`ALLOW`) across all policies. No matching rule anywhere → `ALLOW`
(pass-through, per the note above). Any failure loading/parsing
policies → `DENY`, logged clearly (this is the actual fail-closed case).

## `RiskEngine`

`score({ toolId, actionId, resource, task, policyMatch }) → { deterministicRiskScore, aiAdvisoryScore: null, finalRiskScore, reasonCodes[] }`,
0-100, explainable via `reasonCodes`. This phase's inputs are
necessarily limited — there is no Tool Registry yet (that's Phase 7,
which will add `ToolAction.riskBaseScore`/`mutating`/`destructive` as a
real input; note this explicitly as a Phase 7 integration point, don't
fake a registry now). Deterministic contributors available now:

- The matched policy rule's own `riskWeight`/`riskFloor`, if any.
- Delegation depth (length of the task's ancestor chain from Phase 5) —
  deeper delegation, marginally higher baseline risk.
- A crude keyword heuristic on `actionId` (e.g. contains "delete",
  "disable", "isolate", "block") as a placeholder mutating/destructive
  signal — explicitly documented as temporary, to be replaced by Phase
  7's real tool-action flags.
- No policy match at all → a low baseline score (e.g. 10), not zero
  (nothing is risk-free).

## Wiring into `AuthorizationService`

Extend Phase 5's pipeline (after the existing OpenFGA `check()` step,
before incrementing `executionCount`):

1. `PolicyEngine.evaluate(...)`. `DENY` → return `DENY` immediately.
2. `RiskEngine.score(...)`.
3. Decision: policy effect `REQUIRE_APPROVAL`, OR
   `finalRiskScore > task.riskCeiling` (Phase 5's `riskCeiling` field,
   unused until now — activate it) → return `REQUIRE_APPROVAL`.
4. Otherwise `ALLOW`, increment `executionCount` as before.

`REQUIRE_APPROVAL` is a real, stable response value from this phase
onward — Phase 8 will build the actual approval workflow that lets a
`REQUIRE_APPROVAL` decision eventually resolve to execution. **This
phase does not implement any path to fulfil a `REQUIRE_APPROVAL`
decision** — it's correctly a dead end for now, and that's fine; don't
build a fake approval mechanism to make the tests feel more complete.

## Policy management endpoints (human-facing, JWT-guarded)

`POST /policies` (create + first `DRAFT` version), `POST
/policies/:id/versions` (new `DRAFT` from JSON or YAML body), `POST
/policies/:id/versions/:versionId/publish` (role-gated —
`SECURITY_ADMIN`/`TENANT_OWNER`), `GET /policies/:id` (current published
content), `GET /policies/:id/versions` (full immutable history), `GET
/policies/:id/versions/:versionId` (single version, any format
requested).

## Testing

- A policy `DENY` rule overrides what OpenFGA/task-scope would otherwise
  allow.
- A policy `REQUIRE_APPROVAL` rule produces that outcome even for a
  low-risk-scored action.
- Exceeding `task.riskCeiling` produces `REQUIRE_APPROVAL` even with no
  matching policy rule.
- No matching policy rule + within risk ceiling → `ALLOW` (proves the
  pass-through default, not an accidental deny-by-default regression).
- Publishing a policy version, then attempting to mutate it directly
  (bypass the API, touch the DB row) is not something you can test via
  the API — instead test that the _API_ never exposes any update/delete
  path for a published version, only "create new version"/"publish"/
  "rollback via new version."
- Rollback: publish v1, publish v2, roll back → v3 with v1's content,
  `previousVersionId` chain intact, v1 and v2 both still readable
  unchanged.
- YAML policy content and its JSON equivalent produce identical
  `contentHash`.
- Two published policies both matching the same request combine
  most-restrictive-wins (one says `ALLOW`, the other `DENY` → overall
  `DENY`).
- Simulated policy-load failure (e.g. malformed `content` in a test
  fixture bypassing normal validation) → `DENY`, not a crash or silent
  allow.

## Out of scope this phase

- Actual approval workflow/UI/Temporal (Phase 8) — `REQUIRE_APPROVAL` is
  a dead-end response this phase, by design
- Tool Registry, real per-action risk metadata (Phase 7)
- AI advisory risk scoring (Phase 10) — field exists, stays null
- Kill switches (dedicated later phase)
- Policy GUI editor (Phase 11 — YAML/JSON API only this phase)
