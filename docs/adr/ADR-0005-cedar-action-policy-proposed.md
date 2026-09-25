# ADR-0005 — Cedar for action-level policy, with a parity migration (proposed, conditional)

- **Status:** PROPOSED. Execute only if Phases 1–3 and the re-scoped Phase 4 finish inside their
  budgets (`MANAR-BUILD-SPEC-ADDENDUM-01.md` §A, §G). Until then the existing deterministic rule
  engine is the decision layer (workspace ADR-001 retained).
- **Date:** 2026-09-17
- **Phase:** 4 (conditional)
- **Deciders:** Mohamed approved Cedar in principle (`MANAR-BUILD-SPEC.md` §2); the timing
  condition is Addendum 01

## Context

Today action-level policy is a zod-validated JSON rule set evaluated in process
(`src/policy/policy-content.schema.ts`, `src/policy/policy-engine.service.ts`): first-match within
a policy, most-restrictive across all PUBLISHED policies, `DENY` on any load or parse failure,
effects `ALLOW | DENY | APPROVAL_REQUIRED`, rule fields `toolId`, `actionId`, `resourcePattern`
(exact or `*`), `resourceClassification`, `riskWeight`, `riskFloor`. Relationship questions
(agent → task → tool action) are answered by OpenFGA (`src/authorization/model/manar.fga`).

The rule set cannot express attribute conditions on the target (a user holding a privileged role),
time windows, rate conditions, or system state, and it has no schema validation or analysis
tooling beyond zod. Spec §8 asks for a schema-validated, analysable language with reproducible
decisions and diffs that show what a version newly permits.

Re-scoped Phase 4 (Addendum 01 §E) delivers the reproducibility half on the existing engine: a
durable `Decision` record per authorize/invoke with request and snapshot hashes, byte-identical
replay, and simulation of draft versions against recorded decisions. That work is a precondition
for this ADR: the recorded decisions are the parity corpus.

## Decision (proposed)

1. **Engine.** `@cedar-policy/cedar-wasm` evaluated in process inside manar-api. No network
   dependency is added to the decision path (workspace ADR-004 holds).
2. **Division of labour.** OpenFGA remains the relationship store (ownership, task assignment,
   approver rights). The Cedar request is built from the entity snapshot and OpenFGA lookups that
   the pipeline already performs; Cedar never queries OpenFGA itself.
3. **Schema.** Principal `Agent` (with `AISystem`, `Task`, `Tenant` as attributes and parents);
   resources `User`, `Group`, `Role`, `Alert`, `Incident`; actions are the connector catalog ids;
   context carries `riskClass`, `kind`, `approvalPresent`, `taskCounts`, `systemState`, `time`.
4. **APPROVAL_REQUIRED as two evaluations.** Cedar answers permit/forbid only. Each request is
   evaluated twice: `is_authorized(action)` for permit, then `is_authorized(Approval::"<action>")`
   in a second action namespace whose `permit` policies mean "this needs a human". The mapping is
   fixed: forbid → `DENY`; permit + approval-permit → `APPROVAL_REQUIRED`; permit alone → `ALLOW`;
   no matching permit → `DENY` (default deny). A second namespace is chosen over policy
   annotations because both evaluations then use the same validated, diffable policy language and
   no annotation parsing sits in the decision path.
5. **Store.** `PolicyVersion` content becomes Cedar text plus a schema hash; the existing version
   chain (`prisma/tenant.prisma:481-560`) and the DRAFT → PUBLISHED flow are kept; validation
   against the schema runs on save and an invalid policy cannot leave DRAFT.
6. **Analysis.** Diff between versions is a text diff plus differential testing over the recorded
   corpus, labelled "sampled against recorded decisions, not a proof". The SMT-based Cedar analysis
   toolchain is evaluated with a one-day box; only if it runs in this environment are results
   labelled proven.

### Parity migration plan

1. **Corpus.** Every `Decision` record from Phases 2–4 (inputs, policy version, outcome, reason
   codes) plus synthesised cases covering each reason code, each rule field, `*` versus exact
   resource patterns, classification conditions, `riskFloor` and `riskWeight`, most-restrictive
   resolution across several policies, and evaluator load failure.
2. **Translation.** A one-off translator renders each PUBLISHED JSON policy to Cedar text;
   the rendered text is reviewed and committed as the first Cedar version, not generated at
   runtime.
3. **Shadow mode.** Behind a per-tenant flag, the pipeline evaluates both engines on every request,
   records only the JSON result, and emits a `policy.parity_mismatch` metric and audit event on any
   difference in decision or approval requirement (reason-code text may differ).
4. **Exit criterion.** 100% parity over the corpus and over N days of shadow traffic, or an
   explicitly listed delta approved by Mohamed per item.
5. **Cut-over.** Per tenant, Cedar becomes authoritative; JSON stays evaluated in shadow for one
   more release, then the JSON engine is removed with its own ADR.

## Alternatives considered

- **Keep the JSON rule set and extend it** (workspace ADR-001's position). Cheapest; no new
  dependency; but every new condition type is bespoke code with bespoke validation, and analysis
  tooling would have to be written. Remains the fallback if this ADR is never executed.
- **Cedar with `@approval` annotations** instead of a second namespace. Fewer policies, but the
  approval signal then depends on reading annotations off matched policies, which is outside
  Cedar's validated semantics and harder to diff.
- **OPA/Rego.** Rejected for Governance Manager readability and because it usually runs as a
  sidecar, which would add a network hop to the decision path.

## Consequences

- If executed: policies gain attribute conditions and schema validation; decisions stay
  reproducible because Cedar is pure over its inputs; the console's policy editor changes from a
  form over JSON to Cedar text with validation feedback (EN/AR strings for every validation
  message).
- Cost: roughly the Phase 4 budget again (five to eight days) including the shadow period. This is
  why it is conditional.
- Risk: a subtle semantic difference between "most restrictive across policies" and Cedar's
  forbid-overrides-permit is the likeliest parity failure; the corpus must cover it explicitly.
- If not executed by 11 November: nothing changes at runtime, and this ADR stays PROPOSED with the
  plan above.

## Enforcement-label impact

None. Policy language does not change which paths are brokered; labels are unaffected.
