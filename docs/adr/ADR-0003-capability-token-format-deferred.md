# ADR-0003 — Capability token format: deferred; the task grant set is the capability for November

- **Status:** ACCEPTED as a deferral (no new token format in this release); the format choice itself is DEFERRED to post-November
- **Date:** 2026-09-17
- **Phase:** 3 (recorded at Gate 0 per `MANAR-BUILD-SPEC-ADDENDUM-01.md` §A)
- **Deciders:** Mohamed (Addendum 01); recorded by engineering

## Context

`MANAR-BUILD-SPEC.md` §7 asks for a signed, attenuable, revocable capability per task, with Biscuit
as the default format and ES256 JWT + `jti` denylist and PASETO v4 as the alternatives. Addendum 01
§A corrects the premise: the task and delegation model already carries the capability semantics,
server-side, bound to the agent's mTLS identity.

What exists today (Phase 0 map, branch `feat/phase-1-trust-core`):

- **Grant set on the task.** `Task.allowedToolActions`, `allowedResourceSelectors`,
  `forbiddenActions`, `startsAt`/`expiresAt`, `maxExecutions`/`executionCount`, `riskCeiling`
  (`prisma/tenant.prisma:311-433`). Tuples are written to OpenFGA when the task is created
  (`src/authorization/task-grant-sync.service.ts`).
- **Attenuation.** Delegation computes the parent's effective grant set and rejects a child that is
  not a subset (`src/delegation/delegation.service.ts`, `computeGrantSet` / `isSubset`), with
  `DelegationExceedsParentAuthorityError`. `expiresAt` is clamped to the parent.
- **Liveness and revocation.** Every authorize walks the task's ancestors and denies if any is not
  live (`src/authorization/authorization.service.ts:203`); `POST /tasks/:id/revoke` takes effect on
  the next request of every descendant.
- **Binding.** The task is only usable by its assigned agent, authenticated by the certificate's
  SAN (`src/agent-mtls/agent-mtls.guard.ts`).
- **One-use grants.** Approved actions are redeemed with an HS256 grant JWT bound to a parameter
  hash and consumed atomically (`src/approvals/grant-token.util.ts`, `grant.service.ts:265-377`).

Gaps in that model are known and scheduled (Addendum 01 §D): `riskCeiling` and `maxExecutions` are
not clamped on delegation, child executions do not draw down the parent budget, delegation skips
the kill-switch check, the child does not inherit group and AI-system links, revocation does not
cascade as a state change, and enrolment tokens can be issued for non-ACTIVE agents.

## Decision

1. **No new token format in this release.** Biscuit, PASETO and any new JWT profile are out of
   scope until after 11 November 2026.
2. **The capability is the task's effective grant set**, held by manar-api, bound to the agent's
   mTLS identity, and verified on every action request by the existing pipeline. The per-task tool
   manifest and the governed MCP tool list (Phase 1) are derived from that grant set, so the
   capability is what the model can see.
3. **Phase 3 hardens this model** (clamps, atomic budget draw-down, kill-switch check on
   delegation, inheritance of group and AI-system links, cascading revocation, enrolment refusal
   for non-ACTIVE agents) with the acceptance tests of spec §7.5 minus the token-format cases.
4. **Deferred decision, to be taken post-November:** a portable, offline-verifiable token for
   agents that cross a Manar boundary (federated deployments, multi-hop delegation where the
   downstream verifier is not this manar-api). Candidates and the evaluation criteria are recorded
   below so the decision does not start from zero.

### Deferred evaluation record

| Criterion                                               | Biscuit                   | ES256 JWT + `jti` denylist          | PASETO v4                    |
| ------------------------------------------------------- | ------------------------- | ----------------------------------- | ---------------------------- |
| Public-key verification                                 | yes                       | yes                                 | yes                          |
| Offline attenuation (holder narrows without the issuer) | yes (block append)        | no                                  | no                           |
| Per-block revocation identifiers                        | yes                       | `jti` per token only                | per token only               |
| Policy expressiveness in the token                      | Datalog checks            | claims only                         | claims only                  |
| TS + Python library maturity in this codebase           | unproven (must be spiked) | `jose` already used; PyJWT standard | libraries exist, less common |
| Fit for federated / multi-hop                           | best                      | adequate with a denylist service    | adequate                     |

Reasons to pick Biscuit at that time: offline attenuation is needed. Reasons not to: library
problems actually hit in both TS and Python, or no boundary-crossing use case materialises.

## Alternatives considered

- **Adopt Biscuit now (spec §7 as written).** About six days plus a spike, two new runtime
  dependencies, and a second source of truth for the same facts the task already holds. While every
  agent runs in a Manar-deployed box whose only egress is manar-api, offline verification and
  holder-side attenuation buy nothing the server-side model does not already provide. Rejected for
  November.
- **ES256 JWT capability now.** Cheaper, but still a second representation of the task with no
  attenuation, and its revocation would be a denylist that duplicates the task status. Rejected.
- **Do nothing (leave Phase 3 as designed).** Rejected: the schedule (44 working days, Addendum 01
  §G) cannot absorb it, and the hardening in §D is what the demo story actually needs.

## Consequences

- The "permission slip" of spec §3.2 is real but not portable: it is verifiable only by manar-api.
  Docs and UI must say "task-scoped capability enforced by Manar", never "offline-verifiable token".
- Sub-agent attenuation is enforced at delegation time by the server, not by the token the
  sub-agent holds. The Phase 3 sub-agent demonstration still shows a read-only child that cannot
  mutate.
- Revocation is a state in PostgreSQL (with a Redis cache in later phases), not a revocation
  identifier inside a token. Kill-switch propagation targets stay as in spec §7.3.
- A post-November move to a token format is additive: the token would carry a snapshot of the
  same grant set, and the pipeline order of spec §7.2 already places capability verification
  before policy.

## Enforcement-label impact

None. No action path changes label because of this ADR. The `governed` label continues to be
earned by the Phase 1 box and the Phase 2 brokered execution, not by a token format.
