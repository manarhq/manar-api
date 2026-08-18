import {
  condition,
  defineSignal,
  proxyActivities,
  setHandler,
} from '@temporalio/workflow';
import type { ApprovalActivities } from '../activities/approval-activities.interface';
import type {
  ApprovalDecisionSignal,
  ApprovalWorkflowInput,
  ApprovalWorkflowResult,
} from './approval-workflow.types';

/**
 * `POST /approvals/:id/decide` signals this — the *only* way a running
 * `ApprovalWorkflow` ever learns a human decided. Exported from this same
 * module (rather than a separate file) so client code and the workflow
 * itself always reference the identical signal definition, the documented
 * Temporal TypeScript SDK pattern (see docs/approvals.md).
 */
export const decideSignal = defineSignal<[ApprovalDecisionSignal]>('decide');

/**
 * `import type` only — erased entirely from this file's compiled output
 * (this project's `isolatedModules` tsconfig setting requires the explicit
 * `type` keyword for that erasure to be guaranteed, not just inferred), so
 * `approval.activities.ts`'s real implementation (Prisma queries, HMAC
 * signing, Nest DI) never becomes part of what Temporal's worker bundles
 * into this workflow's deterministic sandbox — Section 28: workflow code
 * contains no I/O of its own, only calls to Activities that do.
 */
const activities = proxyActivities<ApprovalActivities>({
  startToCloseTimeout: '30 seconds',
  retry: {
    initialInterval: '1 second',
    backoffCoefficient: 2,
    maximumInterval: '30 seconds',
    maximumAttempts: 5,
  },
});

/**
 * One `ApprovalWorkflow` execution per `ApprovalRequest` (1:1, via that
 * row's own `temporalWorkflowId`) — durably waits for a human `decide`
 * signal or its own `expiresAt` timeout, whichever comes first, entirely
 * independent of the HTTP process's own uptime (Section 27/28/31; see
 * docs/approvals.md for the full flow this implements).
 *
 * All actual work — recording the decision, re-evaluating whether it still
 * holds, issuing a signed grant, or recording an expiry — happens inside
 * `Activities` (`../activities/approval.activities.ts`), never here. This
 * function only: registers the signal handler, races it against the
 * timeout, and picks which Activity to call based on the outcome. No
 * database access, no HTTP calls, no crypto, no `Math.random()`/real
 * `Date.now()` wall-clock reads other than what Temporal's own
 * deterministic sandbox provides.
 */
export async function ApprovalWorkflow(
  input: ApprovalWorkflowInput,
): Promise<ApprovalWorkflowResult> {
  let receivedSignal: ApprovalDecisionSignal | undefined;

  setHandler(decideSignal, (signal) => {
    // First signal wins. A second `decide` call for a request this
    // workflow already stopped listening on (or is about to) is silently
    // ignored rather than clobbering the first human's decision — there is
    // no code path that sends a second signal for a request whose
    // ApprovalRequest.status is no longer PENDING anyway (see
    // ApprovalsController), but a workflow itself never assumes a caller
    // enforced that.
    if (receivedSignal === undefined) {
      receivedSignal = signal;
    }
  });

  const timeoutMs = Math.max(0, input.expiresAtEpochMs - Date.now());
  const decidedBeforeTimeout = await condition(
    () => receivedSignal !== undefined,
    timeoutMs,
  );

  if (!decidedBeforeTimeout || receivedSignal === undefined) {
    await activities.expireApprovalRequest({
      tenantId: input.tenantId,
      approvalRequestId: input.approvalRequestId,
    });
    return { outcome: 'EXPIRED' };
  }

  const result = await activities.finalizeApprovalDecision({
    tenantId: input.tenantId,
    approvalRequestId: input.approvalRequestId,
    decision: receivedSignal.decision,
    approverId: receivedSignal.approverId,
    reason: receivedSignal.reason,
  });

  if (result.status === 'APPROVED' && result.grantId) {
    return { outcome: 'APPROVED', grantId: result.grantId };
  }
  return { outcome: 'DENIED' };
}
