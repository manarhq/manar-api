# ADR-0001 — Capability-based enforcement: remove the authority to misbehave

- **Status:** ACCEPTED; amended 2026-09-17 by `MANAR-BUILD-SPEC-ADDENDUM-01.md` (phase re-scopes
  recorded below)
- **Date:** 2026-09-17
- **Phase:** 0 (governs Phases 1–9)
- **Deciders:** Mohamed (founder), via `MANAR-BUILD-SPEC.md` and Addendum 01; recorded by engineering

## Context

Manar sits between autonomous AI agents and the enterprise systems they can affect. Most tooling
in this space watches agents and tries to catch misbehaviour after it starts. Detection has false
negatives and acts late, so an agent holding its own credentials and open network egress can do
damage before anyone notices.

What manar-api does today (Phase 0 mapping, branch `feat/phase-1-trust-core`, HEAD `18e25e9`):

- Agents get X.509 identities from an OpenBao-held CA via CSR enrollment and authenticate on
  the mTLS listener (`src/agents/certificate-authority.service.ts`,
  `src/agent-mtls/agent-mtls.guard.ts`; `test/agent-identity.e2e-spec.ts`).
- Authorization runs kill switches, task liveness, OpenFGA `can_use`, JSON policy rules and an
  additive risk score (`src/authorization/authorization.service.ts:127-374`). manar-ai is not on
  that path (`src/authorization/decision-path-dependencies.spec.ts`).
- The generic broker-executes path exists: `POST /agent/v1/tools/invoke` →
  `CredentialBrokerService` → `HttpToolAdapter` / `McpToolAdapter`, with credentials resolved from
  OpenBao KV that never return to the agent (`src/tools/credential-broker.service.ts`). It runs
  against in-repo demo fixtures only; no Microsoft connector, OAuth2 client-credentials provider,
  typed action catalog or tool-registration API exists.
- The task and delegation model already carries capability semantics: per-task grant sets,
  subset-checked delegation, an ancestor liveness walk on every authorize, and one-use grant JWTs
  bound to a parameter hash (`src/tasks/`, `src/delegation/`, `src/approvals/grant.service.ts`).
- Missing: an agent runtime Manar deploys, egress control for agents, an LLM proxy, a per-task
  tool manifest, a northbound MCP server, a durable decision record, quarantine, tripwires,
  fail-closed per-task limits, and signed checkpoints with offline verification. Evidence bundles
  are HS256-signed with a shared secret (`src/evidence/evidence-signing.util.ts`), so they cannot
  be verified offline.

## Decision

Manar enforces by removing authority, not only by observing behaviour. Seven properties, each
built in a gated phase of `MANAR-BUILD-SPEC.md` as re-scoped by Addendum 01:

| Property                   | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                     | Phase                     |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| No keys                    | The agent holds no credential to any target system. Manar's connectors execute on its behalf with credentials fetched from OpenBao. Phase 2 extends the existing gateway with an OAuth2 client-credentials provider and a typed Graph/Entra and Defender XDR action catalog.                                                                                                                                                | 1 (agent), 2 (connectors) |
| No exits                   | The agent workload can reach only manar-api (Compose `internal` network; Kubernetes default-deny NetworkPolicy with a preflight that fails the release when the CNI does not enforce). LLM calls go through Manar's OpenAI-compatible proxy, upstreaming to Ollama first and Azure OpenAI second. The per-task tool manifest and the governed MCP server are built here, derived from the task's grant set.                 | 1                         |
| Permission slips           | The task's effective grant set is the capability: bound to the agent's mTLS identity, verified before policy, narrowed only on delegation, revoked by task or system state. Phase 3 hardens it (clamps, atomic budget draw-down, kill-switch check on delegation, inheritance of group and AI-system links, cascading revocation, enrolment refusal for non-ACTIVE agents). No new token format this release; see ADR-0003. | 3                         |
| Written, analysable policy | The existing deterministic rule engine, with a durable `Decision` record per authorize/invoke, byte-identical replay, and simulation of draft versions against recorded decisions, labelled "sampled, not a proof". Cedar is proposed in ADR-0005 and runs only if Phases 1–4 finish inside budget. OpenFGA keeps relationships.                                                                                            | 4                         |
| Tripwires                  | Decoy tools and canary secrets detect prompt injection deterministically; injection findings block and flag rather than annotate.                                                                                                                                                                                                                                                                                           | 6                         |
| Quarantine                 | Mutations are captured instead of executed while a human reviews.                                                                                                                                                                                                                                                                                                                                                           | 7                         |
| Tamper-evident record      | Signed (Ed25519, key held in OpenBao) periodic checkpoints of the per-tenant hash chain, signed evidence bundles with the public key exported, scheduled retention anchors, and a standalone offline verifier. Merkle inclusion proofs and witness publication move post-November.                                                                                                                                          | 8                         |

Fail-closed per-task and per-system limits (Phase 5) and demo hardening (Phase 9) complete the
plan. The scripted demo against `packages/demo-soc-tools` (`scripts/demo-agent.ts`,
`test/complete-demo.e2e-spec.ts`) is the rehearsed fallback for 11 November and must keep passing
through every phase.

Invariants that hold across every phase:

1. A decision is a pure function of (policy version, entity snapshot, request, capability). An
   LLM, heuristic or anomaly score may escalate a decision and never relax one.
2. Failure of identity, tenant resolution, authorization, capability verification, revocation
   lookup, the limits store or kill-switch state yields DENY with reason
   `enforcement_dependency_unavailable`.
3. MCP and REST are two entry points to one decision pipeline.
4. An enforcement label is earned by the mechanism above, never declared.

Reuse over rebuild: the agent CA and mTLS guard are the identity the capability binds to; the
tool gateway, OpenFGA, Temporal approvals, kill switches and the audit hash chain are extended
rather than replaced. Detailed choices are recorded in later ADRs: ADR-0002 (LLM proxy placement
and retention), ADR-0003 (capability token format, deferred), ADR-0004 (connector execution and
credentials), ADR-0005 (Cedar, proposed).

## Alternatives considered

- **Observe-and-detect (behaviour monitoring, SIEM correlation) as the primary control.** Rejected
  as the primary control: it acts after the fact and cannot stop an agent that holds its own
  credentials. Monitoring stays as a secondary signal that can only add restriction.
- **Let agents keep target-system credentials, gated by a Manar authorization call.** This is
  close to the tool gateway's original model. Rejected: an agent that skips the call still holds
  the credential, so the path could only be labelled `observed-only`, never `governed`.
- **An LLM judge deciding authorization.** Rejected by invariant 1: not reproducible, and it can
  be steered by the injected content it is meant to police.
- **A new signed capability token (Biscuit) and Cedar in this release** (the spec as first
  written). Deferred by Addendum 01: the task model already provides the capability semantics and
  the schedule cannot absorb two new engines. Recorded in ADR-0003 and ADR-0005.

## Consequences

- The `governed` label becomes a verifiable property of the deployment (no credential, no route
  out, capability checked) rather than a registry flag.
- Manar is on the critical path for every agent action and every LLM call. Its availability and
  decision latency now bound agent throughput; Phase 9 measures ALLOW-path p95 against 150 ms.
- A customer's agents must run as Manar-deployed workloads to earn `governed`. Agents on external
  platforms can be at most `observed-only` for actions they can reach without Manar.
- About 44 working days of work against 55 calendar days to 11 November 2026 (Addendum 01 §G).
  Order of protection if the schedule slips: 0 → 1 → 3 → 2 → 6 → 7 → 9 → 8 → 4 → 5.
- Existing behaviour that conflicts with this ADR is fixed before the agent runtime is written
  (Phase 1 prerequisites, Addendum 01 §B.1, §C.1): retries of mutating and destructive actions
  with no `UNKNOWN` outcome, audit-write failure that does not stop execution, the agent listener's
  unhandled 500 when Redis is down, delegation that can widen authority, enrolment tokens for
  revoked agents, and injection findings that only annotate.

## Enforcement-label impact

None at the time of this ADR: no path changes until Phase 1 lands. After Phase 1 the demo agent
may be labelled `governed` only when it is deployed by the Manar chart or Compose profile and the
egress preflight passed. Every later phase states its own label impact.
