# Release 2026-11-11 — dependency-aware implementation plan

Written 2026-09-08, the brief's own planning baseline, so the workback
calendar in brief §10 starts unshifted. Progress against it is tracked in
`STATE.md`; blockers in `BLOCKERS.md`; decisions in `DECISIONS.md`.

Work is organised as vertical slices — schema/contract → backend
authorization/workflow → frontend → telemetry → tests — rather than by
layer, because the brief requires the redesigned anomaly workflow to reach
a working integrated state early rather than leaving UI to the last week.

## Slice order and why

The order below is a dependency order, not a priority order. Two things
force it:

1. **`AiSystem` is the record everything else attaches to.** Findings,
   investigations, assessments and evidence all reference a governed
   system. Building any of them first would mean building them twice.
2. **Contract changes propagate outward.** `manar-web`'s typed client is
   generated from `manar-api`'s live OpenAPI document, and its own rules
   forbid hand-editing the generated schema. So every API surface must
   exist and be stable before the matching UI work starts, and the API must
   be running for the client to regenerate at all.

| #   | Slice                                                                   | Depends on | Status             |
| --- | ----------------------------------------------------------------------- | ---------- | ------------------ |
| 0   | Baseline: bootstrap, gates, route/dependency inventory, security triage | —          | **done**           |
| 1   | AI-system inventory: schema, migration, service, API, tests             | 0          | **done (backend)** |
| 2   | Critical security fixes: BFF host injection, MCP resource clobber       | 0          | **done**           |
| 3   | Remaining auth/SSRF/reliability/deployment blockers                     | 0          | in progress        |
| 4   | Approval context: expose the reviewed parameter snapshot end to end     | 1          | not started        |
| 5   | Findings/anomaly detection vertical slice                               | 1, 3       | not started        |
| 6   | Server-side aggregates for the overview                                 | 1, 5       | not started        |
| 7   | Design system: tokens, density, theme-from-system-preference            | 0          | not started        |
| 8   | AI-systems console surface                                              | 1, 7       | not started        |
| 9   | Findings queue + investigation workspace UI                             | 5, 6, 7    | not started        |
| 10  | Decision explorer (replaces the placeholder authorization route)        | 3, 7       | not started        |
| 11  | Policy simulation against the deterministic evaluator                   | 10         | not started        |
| 12  | Connector onboarding and real health checks                             | 3          | not started        |
| 13  | Authorized RAG retrieval flow + evaluation datasets                     | 5, 12      | not started        |
| 14  | Evidence bundles, assessments, reporting                                | 4, 5, 9    | not started        |
| 15  | Failure-policy model                                                    | 3          | not started        |
| 16  | Deployment hardening, upgrade/restore exercises, load                   | 3, 12      | not started        |

## Slice detail for the next three

### Slice 3 — remaining blockers (in progress)

Three parallel workstreams with disjoint file ownership, tracked as B3–B16
in `BLOCKERS.md`:

- **Auth and egress** (`manar-api`): JWT audience/algorithm pinning,
  constant-time secret comparison, redirect-aware SSRF with credential
  stripping on cross-origin hops, response size limits.
- **Reliability and deployment** (`manar-api`): dependency-aware readiness
  that keeps optional-AI degradation out of the failure path, health-route
  throttler exemption, graceful shutdown, batched chain verification,
  bootable Helm charts.
- **Transport and egress** (`manar-ai`): mTLS with peer verification and a
  production plaintext refusal, environment-gated authenticated debug
  surface, deterministic redaction before any external model call.

The `manar-ai` mTLS work produces a client-side change `manar-api` must
make in step (`ai-advisory-client.service.ts` currently uses
`createInsecure()`). That coupling is why the two are not being changed by
the same agent at the same time — the server side lands first, keeping the
dev plaintext path working, and the client follows once the exact config
keys and expected peer identity are known.

### Slice 4 — approval context

B17: the grant mechanism is sound (one-use redemption via a conditional
update, parameter-hash binding, kill-switch recheck) but the human
approver never sees the parameters the grant binds. This is the API half of
a gap `manar-web` correctly refused to paper over — its approval detail
view renders explicit "unavailable" panels rather than fabricating fields.

Work: extend `ApprovalRequestSummaryDto` with a safely redacted parameter
snapshot and a structured explanation of _why_ approval was required
(deterministic factors and separately attributed AI signals, per brief
§3.3), add a human `GET /approvals/:id`, then regenerate the web client and
replace the placeholders. Redaction is viewer-permission-dependent, so the
DTO must be built server-side rather than shipping raw request rows.

### Slice 5 — findings and anomaly detection

The brief is explicit that this must be bounded and explainable before any
broad ML, and that a detector may only be claimed to work when its input
telemetry exists. The first detectors are therefore chosen by what this
platform already records reliably:

- **Repeated denials / out-of-scope requests** — `authorization.denied`
  audit events exist today, per agent, with correlation IDs.
- **Unusual tool/action volume relative to that agent's own baseline** —
  `ToolInvocation` rows exist with `startedAt`, agent, tool and action.
  Median/MAD over a rolling window, with an explicit minimum sample count.
- **Newly observed tool or action for an agent after a meaningful
  observation period** — derivable from the same rows, gated on a warmup.

Deliberately **not** in the first cut, because the telemetry to support
them is not reliably present: delegation-depth anomalies, destination
policy violations beyond what `ToolAction.classification` already encodes,
and provider/configuration drift (which needs slice 12's connector health
first).

Schema will carry the brief's required separations as distinct columns
rather than one blended score: detector key and version, event/ingest/
detection timestamps, observed vs expected values, baseline completeness
(including an explicit `INSUFFICIENT_HISTORY`, which is neither anomalous
nor safe), severity with its rationale, confidence, evidence references,
and a deduplication key. Findings are informational by default; any
automated restriction must go through a versioned deterministic response
rule, never because an LLM described something.

## Schedule assessment

The brief requires reporting schedule risk rather than asserting the date
is achievable. As of the baseline date:

**On track.** Slice 0 and the two critical security fixes landed on day one,
and slice 1's backend is complete with 33 passing unit tests. The
foundation the brief's Sep 15–28 milestone calls for (contract/persistence
foundations, safe-execution and audit fixes, system inventory) is
substantially underway ahead of that window.

**The three things most likely to move the date:**

1. **Integration verification (§7) is gated on access this workspace does
   not contain.** Every "real vendor" integration in the inventory is
   currently a demo fixture. Per §7 the honest outcome for those is
   **blocked/unverified**, not a pass — and the brief's release gate says
   missing access is an explicit blocker. The independent work (protocol,
   connector infrastructure, health model, failure tests) can and will be
   finished regardless, but the gate itself cannot close without either
   real vendor test tenants or an owner decision to descope specific
   connectors. **This needs an owner input, and it needs it early enough to
   matter.**
2. **The AI quality gate needs a corpus that does not exist yet.** §5 asks
   for a versioned, manually reviewed grounded-Q&A set of at least 100
   cases with 70/30 answerable/insufficient-evidence partitions. Building
   and _reviewing_ that is human-time-expensive and cannot be compressed by
   generating it synthetically — synthetic data must be labelled as such
   and cannot stand in for production accuracy. If no representative
   customer traces become available, §5 requires stating that limitation
   and shipping the replay procedure instead; that is the realistic outcome
   and should be planned for, not discovered in November.
3. **Load, upgrade and restore exercises (§9, §11) need an environment that
   resembles the sizing hypothesis.** The three-node 8 vCPU/32 GiB profile
   is a labelled hypothesis, not a provisioned environment. Benchmarks run
   on a developer machine are not evidence for those targets, and reporting
   them as if they were would violate §9 directly.

**Not currently a risk:** the redesign scope. The existing design system,
RTL/i18n discipline and component library are in better shape than the
brief's baseline assumes — EN/AR are at exact key parity, logical CSS
properties are already the convention, and reduced-motion is handled
globally rather than per-component. The two real gaps are that no density
preference exists at all and that the theme is pinned to dark with
`enableSystem={false}`, both of which the brief requires and both of which
are contained work.
