# ADR-0001 — Capability-based enforcement: remove the authority to misbehave

- **Status:** ACCEPTED
- **Date:** 2026-09-17
- **Phase:** 0 (governs Phases 1–9)
- **Deciders:** Mohamed (founder), via `MANAR-BUILD-SPEC.md`; recorded by engineering

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
- A credential broker already executes tool calls on the agent's behalf through
  `HttpToolAdapter` and `McpToolAdapter` (`src/tools/credential-broker.service.ts`), against
  in-repo demo fixtures only. No Microsoft connector exists.
- Missing: an agent runtime Manar deploys, egress control for agents, an LLM proxy, per-task
  capability tokens, a durable decision record, quarantine, tripwires, fail-closed per-task
  limits, and a Merkle log with offline verification. Evidence bundles are HS256-signed with a
  shared secret (`src/evidence/evidence-signing.util.ts`), so they cannot be verified offline.

## Decision

Manar enforces by removing authority, not only by observing behaviour. Seven properties, each
built in a gated phase of `MANAR-BUILD-SPEC.md`:

| Property                   | Meaning                                                                                                                                                                                                                    | Phase                     |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| No keys                    | The agent holds no credential to any target system. Manar's connectors execute on its behalf with credentials fetched from OpenBao.                                                                                        | 1 (agent), 2 (connectors) |
| No exits                   | The agent workload can reach only manar-api (Compose `internal` network; Kubernetes default-deny NetworkPolicy with a preflight that fails the release when the CNI does not enforce). LLM calls go through Manar's proxy. | 1                         |
| Permission slips           | Every task carries a signed, attenuable, revocable capability, bound to the agent's mTLS identity and verified before policy. Suspension revokes.                                                                          | 3                         |
| Written, analysable policy | Action-level policy in Cedar, versioned, schema-validated, replayable; diffs labelled proven or sampled. OpenFGA keeps relationships.                                                                                      | 4                         |
| Tripwires                  | Decoy tools and canary secrets detect prompt injection deterministically.                                                                                                                                                  | 6                         |
| Quarantine                 | Mutations are captured instead of executed while a human reviews.                                                                                                                                                          | 7                         |
| Tamper-evident record      | RFC 6962-style Merkle log, signed checkpoints, standalone offline verifier.                                                                                                                                                | 8                         |

Fail-closed per-task and per-system limits (Phase 5) and demo hardening (Phase 9) complete the plan.

Invariants that hold across every phase:

1. A decision is a pure function of (policy version, entity snapshot, request, capability). An
   LLM, heuristic or anomaly score may escalate a decision and never relax one.
2. Failure of identity, tenant resolution, authorization, capability verification, revocation
   lookup, the limits store or kill-switch state yields DENY with reason
   `enforcement_dependency_unavailable`.
3. MCP and REST are two entry points to one decision pipeline.
4. An enforcement label is earned by the mechanism above, never declared.

Reuse over rebuild: the agent CA and mTLS guard become the identity the capability binds to;
OpenFGA, Temporal approvals, kill switches and the audit hash chain are extended rather than
replaced. Detailed choices are recorded in later ADRs: ADR-0002 (LLM proxy placement), ADR-0003
(capability token format), ADR-0004 (connector execution and credentials), ADR-0005 (Cedar).

## Alternatives considered

- **Observe-and-detect (behaviour monitoring, SIEM correlation) as the primary control.** Rejected
  as the primary control: it acts after the fact and cannot stop an agent that holds its own
  credentials. Monitoring stays as a secondary signal that can only add restriction.
- **Let agents keep target-system credentials, gated by a Manar authorization call.** This is
  close to the tool gateway's original model. Rejected: an agent that skips the call still holds
  the credential, so the path could only be labelled `observed-only`, never `governed`.
- **An LLM judge deciding authorization.** Rejected by invariant 1: not reproducible, and it can
  be steered by the injected content it is meant to police.

## Consequences

- The `governed` label becomes a verifiable property of the deployment (no credential, no route
  out, capability checked) rather than a registry flag.
- Manar is on the critical path for every agent action and every LLM call. Its availability and
  decision latency now bound agent throughput; Phase 9 measures ALLOW-path p95 against 150 ms.
- A customer's agents must run as Manar-deployed workloads to earn `governed`. Agents on external
  platforms can be at most `observed-only` for actions they can reach without Manar.
- Roughly 48 working days of work against 55 calendar days to 11 November 2026. Phases 1–3 carry
  the core claim and are protected; Phases 4–8 are cut from their "if over budget" columns first.
- Existing assumptions change: the tool gateway's retry of non-idempotent calls, the missing
  decision record, and the HS256 evidence signature all conflict with this ADR and are closed in
  Phases 2 and 8.

## Enforcement-label impact

None at the time of this ADR: no path changes until Phase 1 lands. After Phase 1 the demo agent
may be labelled `governed` only when it is deployed by the Manar chart or Compose profile and the
egress preflight passed. Every later phase states its own label impact.
