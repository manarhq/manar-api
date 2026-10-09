# ADR-0006 — The decision commits with its reservation, and grant redemption re-decides

- **Status:** ACCEPTED
- **Date:** 2026-10-07
- **Phase:** 1 (execution-path prerequisites); lays the record Phase 4 (decisions, replay) builds on
- **Deciders:** engineering judgement, implementing workspace ADR-003 and security findings S1, S6/F7

## Context

Workspace `docs/adr/ADR-003-durable-decision-before-execution.md` requires the decision record to
commit in PostgreSQL before anything executes, and in the same transaction as the grant
consumption (ALLOW) or approval creation (APPROVAL_REQUIRED). Before this change no `Decision`
model existed: `CredentialBrokerService.invoke` contacted the tool and only then wrote a
`ToolInvocation` row (finding S1).

Separately, redeeming an approval grant (`POST /agent/v1/tools/invoke` with `grantToken`) checked
signature, parameter binding, task liveness and kill switches, then executed. It did not re-run
OpenFGA or the current policy version (finding S6/F7; spec §6.2: "on approve, re-run the whole
pipeline"). It also counted the grant's own execution twice: `executionCount` is incremented at
grant issuance, and redemption then ran the full liveness check, so a task whose `maxExecutions`
was reached by that increment could never redeem its grant.

## Decision

1. **One `Decision` row per action request**, tenant DB (`prisma/tenant.prisma`, migration
   `20261007100000_add_decision_record`): outcome, reason codes (decisive reason first, then
   deterministic risk codes), matched policy id and version id, risk score, inputs hash
   (`computeParameterHash`, the hash approval grants already bind to), agent, task, tool, action,
   resource, channel (`REST`, `MCP`, `AUTHORIZE`), stage (`REQUEST`, `GRANT_REDEMPTION`), grant id,
   correlation id, `createdAt`. Append-only. No foreign keys to `Task` or `Agent`, because a DENY
   for an unknown task is still a decision.
2. **`AuthorizationService.evaluate` only reads; `commit` writes.** For ALLOW, the reservation
   (execution-count increment on a first attempt, grant consumption on redemption) and the
   `Decision` insert share one interactive transaction. Losing the reservation race records DENY
   (`task_execution_limit_reached` or `grant_already_consumed`). DENY and APPROVAL_REQUIRED
   insert without a transaction because they reserve nothing.
3. **Fail closed.** Any failure in `commit` is a 503 `enforcement_dependency_unavailable`
   (`failClosed('decision-store')`); the caller gets no `decisionId` and the broker is never
   called. A dependency failure inside `evaluate` is still a recorded DENY.
4. **Execution is addressed by decision id.** `CredentialBrokerInvokeInput.decisionId` is
   required; `ToolInvocation.decisionId` links SUCCESS/FAILURE/UNKNOWN back; every authorization,
   broker and grant audit event carries `decisionId`.
5. **Redemption re-decides** (`AuthorizationService.authorizeRedemption`), after
   `GrantService.verifyGrant` has checked the token is for this exact request. It re-runs kill
   switches (platform, tenant, agent, agent group, tool), AI-system lifecycle, assignment, task and
   ancestor liveness and TTL, forbidden actions, OpenFGA and the current policy. Only DENY refuses.
   A policy APPROVAL_REQUIRED and the risk ceiling do not, because a human approved this exact
   request with its parameters. The task's own execution limit treats this request as already
   counted. An invalid grant is a recorded DENY too.

## Alternatives considered

- **Write the decision after execution, or in the broker.** That is the S1 defect.
- **Write the decision outside the reservation transaction.** A crash between the two leaves
  either a consumed budget or grant with no decision, or a decision whose reservation never
  happened. The transaction costs one round trip on ALLOW only.
- **Redemption: refuse on any change from ALLOW, including APPROVAL_REQUIRED.** Every approved
  request would be refused, since APPROVAL_REQUIRED is why it was approved.
- **Redemption: re-score risk and refuse above the ceiling.** Same problem: the score was above
  the ceiling when the human approved it. A score that rises because of new deterministic signals
  (an agent risk flag) is not checked again; a kill switch or AI-system suspension is the control
  for that.
- **Keep kill-switch and liveness checks in `GrantService`.** Two copies of the pipeline drift; the
  redemption now runs the same `evaluate` as a first attempt.
- **Transactional outbox for audit and Kafka in the same change.** ADR-003 assigns it to Phase 2.
  Audit stays `recordSafely` after the commit; the `Decision` row is the durable record.

## Consequences

- PostgreSQL availability bounds every decision, including `POST /agent/v1/authorize` and DENY.
  This is the fail-closed direction ADR-003 accepts. p95 cost of the extra insert is not yet
  measured.
- `POST /agent/v1/authorize` responses and the DENY 403 body gain `decisionId` (additive).
- A DLP before-call block, a disabled tool or an unknown tool after an ALLOW decision leaves an
  ALLOW `Decision` with no SUCCESS row: disabled tools write a FAILURE row; DLP blocks and unknown
  tools are visible only through audit events that carry the `decisionId`. A decision records
  authorization, not that the tool ran.
- Approval-time re-evaluation in `GrantService.finalizeDecision` is grant issuance, not an action
  request, and writes no `Decision`; the redemption that follows does.
- Replay (Phase 4) still needs the entity snapshot hash and per-policy trace; this record has the
  inputs hash, policy version and reason codes it will extend.
- Rollback: revert the code commits, then the migration's rollback statements. Decision history
  is lost if the table is dropped.

## Enforcement-label impact

None changes label. This closes S1 and S6/F7 on the existing `governed` tool path (REST and MCP
doors): every governed action now has a durable, pre-execution decision record, and an approval
can no longer be redeemed after policy, entitlement, task or kill-switch state turned to DENY.
Evidence: `src/authorization/authorization.decision-record.spec.ts`,
`src/authorization/authorization.redemption.spec.ts`, `src/tools/tool-invocation.service.spec.ts`,
`test/approvals.e2e-spec.ts` (1, 7b, 7c), `test/agent-runtime.e2e-spec.ts` (MCP door).
