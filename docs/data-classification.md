# Data classification (Phase 15a, Section 53)

This is `manar-api`'s implementation of Section 53 of the master prompt:
`docs/superpowers/specs/2026-08-19-phase15a-classification-compliance-incidents-design.md`.
It adds a data-sensitivity tag to the one place this codebase already
tracks a specific, executable action — `ToolAction` — and threads it
through three independent enforcement points. Read
`docs/policy-model.md` and `docs/ai-security-model.md` first; this
document only covers what Phase 15a itself added on top of them.

## The enum

`DataClassification` (`prisma/tenant.prisma`, mirrored as a plain TS/Zod
artifact in `src/common/data-classification.ts`, the same "small shared
constant, not a re-derivation" posture `src/auth/roles.ts`'s `ROLES`
establishes for `Role`):

```
PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
```

`ToolAction.classification` defaults to `INTERNAL`, **not** `PUBLIC`
— the safer default (Section 53). A `ToolAction` row written before this
phase existed was backfilled to `INTERNAL` by this phase's migration
(`prisma/tenant/migrations/20260819060722_add_data_classification/migration.sql`),
not `PUBLIC`.

There is still no human-facing `Tool`/`ToolAction` registration API
(unchanged from Phase 7b/11b — see `docs/tool-gateway.md`'s "out of
scope" note) — `classification` is set the same way every other
`ToolAction` column is set today: written directly against the tenant
database (see `src/cli/commands/demo-seed.command.ts`'s demo seed, which
sets `iam.disable-user`'s classification to `RESTRICTED`) or by a test
fixture.

## Enforcement point 1: `PolicyEngine`'s `resourceClassification` rule condition

`PolicyRuleSchema` (`src/policy/policy-content.schema.ts`) gains an
optional `resourceClassification` field, matched exactly like every other
condition on a rule (Section 21's first-match-wins, exact-or-absent
semantics — see `docs/policy-model.md`): when present, a rule only
matches a request whose resolved `ToolAction.classification` equals it.

`PolicyEngine.evaluate` now depends on `ToolRegistryService` (mirroring
the exact same dependency `RiskEngine` already carries — see
`docs/tool-gateway.md`) to resolve `{toolId, actionId}` against a real
`ToolAction` row once, before evaluating any policy's rules. A
`{toolId, actionId}` pair with no registered `ToolAction` at all has no
known classification, so a rule carrying `resourceClassification` never
matches it — the same "not registered is not a match" posture
`RiskEngine`'s own `ToolAction` lookup already established. A failure to
resolve the lookup itself (a database error, not "not registered") is
logged and treated the same way — no classification-conditioned rule can
match, but this does **not** fail the whole evaluation closed the way a
genuine policy-load/parse failure does (Section 22's fail-closed case
stays scoped to policy content itself, not this optional side lookup).

**Nothing is hardcoded to auto-deny on `RESTRICTED`.** A policy author
decides what, if anything, a classification implies — that's what
`PolicyEngine` rules are for. This phase seeds one real, worked example
demonstrating the pattern (`src/cli/commands/demo-seed.command.ts`'s
`DEMO_POLICIES`, "Restricted Classification Approval Policy"):

```yaml
rules:
  - name: Require approval for RESTRICTED-classified actions
    toolId: '*'
    actionId: '*'
    effect: REQUIRE_APPROVAL
    resourceClassification: RESTRICTED
    riskWeight: 50
    riskFloor: 65
```

The demo tenant's one `RESTRICTED`-classified `ToolAction`
(`iam.disable-user`) is what this rule is written to match — see
`test/data-classification.e2e-spec.ts` for it exercised through the real
`AuthorizationService.authorize` pipeline.

## Enforcement point 2: `RiskEngine`'s classification contributor

`RiskEngine.score` (`src/risk/risk-engine.service.ts`) adds one more
deterministic contributor when a `ToolAction` is registered —
`CLASSIFICATION_RISK_POINTS`:

| Classification | Points |
| -------------- | -----: |
| `PUBLIC`       |      0 |
| `INTERNAL`     |      0 |
| `CONFIDENTIAL` |     10 |
| `RESTRICTED`   |     25 |

Recorded as `tool_action_classification:<value>:<points>` in
`reasonCodes` whenever a `ToolAction` is registered — even a `0`-point
`PUBLIC`/`INTERNAL` contribution, mirroring `tool_action_risk_base`'s
identical "always recorded when registered, regardless of value"
posture, so a score is always fully explainable from the response alone.
`PUBLIC`/`INTERNAL` contribute nothing beyond the flat baseline every
request already gets — `INTERNAL` is the schema default, so an
unclassified-in-practice action's score is unaffected by this phase.
`CONFIDENTIAL`/`RESTRICTED` step up meaningfully but deliberately not
enough alone to force `REQUIRE_APPROVAL` for every such action on their
own — that combination is what a `resourceClassification` policy rule's
own `riskWeight`/`riskFloor` is for (enforcement point 1, above).

## Enforcement point 3: `AiAdvisoryClient`'s independent residency gate

Section 53's own worked example: _"RESTRICTED data cannot be sent to an
external cloud AI provider."_ Phase 12a's `AiAdvisoryClient` already
gates every call to an external provider on `Tenant.allowExternalAi`
(`residencyAllows`, see `docs/ai-security-model.md`). This phase adds a
**second, independent** gate to the exact same method: a
`RESTRICTED`-classified tool action's data is never sent to an external
provider, **regardless** of whether the tenant has
`allowExternalAi = true`.

```
residencyAllows(tenantId, rpcName, classification):
  if provider is not external -> allowed (unaffected by classification)
  if classification == RESTRICTED -> BLOCKED (no tenant lookup needed)
  else -> falls through to the existing allowExternalAi check
```

Checked _before_ the `allowExternalAi` tenant lookup, for two reasons:
it needs no control-DB round trip at all (a classification-level
restriction doesn't depend on tenant configuration), and a permissive
tenant flag must never be able to bypass it — a tenant that generally
allows external AI still may never leak a `RESTRICTED` action's data
that way.

`analyzeRisk`/`analyzeDlp`/`analyzePromptInjection` all gained an
optional `classification` parameter, threaded through by their callers:

- `RiskEngine.score` passes the resolved `ToolAction.classification` (or
  `undefined`, if unregistered) into `analyzeRisk`.
- `CredentialBrokerService.invoke`'s before-call DLP checkpoint and its
  post-call DLP/prompt-injection advisories (`docs/ai-security-model.md`)
  all pass the invoked action's own `action.classification`.

On a block, this returns the _exact same_ "no AI signal available" `null`
outcome every other reason `AiAdvisoryClient` skips a call already
produces (Section 80's fail-secure invariant) — no new response shape,
and every existing caller already treats `null` correctly. A residency or
classification block never counts toward the circuit breaker (a policy
decision, not an outage) — see `docs/ai-security-model.md`.

`test/data-classification.e2e-spec.ts`'s dedicated scenario asserts this
at the transport level, mirroring Phase 12a's own residency test pattern:
zero RPC attempts reach the fake gRPC server for a `RESTRICTED` action,
even when the tenant's `allowExternalAi` is `true`.

## Migration

`prisma/tenant/migrations/20260819060722_add_data_classification/migration.sql`
— adds the `DataClassification` enum and `ToolAction.classification`
column (`NOT NULL DEFAULT 'INTERNAL'`, backfilling every existing row).

## `GET /tools` already surfaces classification — no `/integrations` backend needed

`ToolActionSummaryDto` (`src/tools/tools.dto.ts`, `GET /tools`, Phase
11b) now includes `classification` on every embedded `ToolAction` row —
confirming Section 60's `/integrations` page (an alternate framing of
`GET /tools`, per this phase's design spec) already has everything a
frontend integrations view would need, including this phase's new field,
without any new backend surface. See `docs/compliance-mapping.md` for the
same confirmation restated alongside this phase's other two subsystems.

## Out of scope this phase

- No enforcement point auto-denies on classification alone — every
  restriction is policy-authored (enforcement point 1) or additive risk
  (enforcement point 2), never hardcoded.
- No classification propagation into `ToolInvocation`/`AuditEvent` rows
  beyond what `RiskEngine`'s `reasonCodes` and the audit trail's existing
  `toolId`/`actionId` fields already imply (a reader can always re-derive
  an action's classification from the live `ToolAction` row).
- No bulk reclassification tooling/API — a `ToolAction.classification`
  value is set exactly like every other column on that model today
  (direct database write; there is still no human-facing registration
  API for the Tool Registry).
