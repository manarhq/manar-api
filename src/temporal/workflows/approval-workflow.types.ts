/**
 * Pure data shapes shared between `ApprovalWorkflow` itself
 * (`approval.workflow.ts`, runs inside Temporal's deterministic sandbox)
 * and the regular Node code that starts/signals it (`ApprovalRequestService`,
 * `ApprovalsController`). No behavior, no imports — safe to import from
 * either side without pulling anything non-deterministic into the
 * workflow's own bundle (see `approval.workflow.ts`'s doc comment).
 */

export interface ApprovalWorkflowInput {
  tenantId: string;
  approvalRequestId: string;
  /**
   * Epoch milliseconds, not a `Date` — plain JSON-serializable, and
   * `Date.now()` inside the workflow sandbox is itself deterministic
   * (Temporal's own workflow-time override), so comparing two numbers is
   * both simpler and avoids any ambiguity about which `Date` construction
   * path is "the deterministic one."
   */
  expiresAtEpochMs: number;
}

export interface ApprovalDecisionSignal {
  decision: 'APPROVE' | 'DENY';
  /** `UserProfile.id` of the human who decided — `POST /approvals/:id/decide`'s authenticated caller, never client-supplied. */
  approverId: string;
  reason?: string;
}

export type ApprovalWorkflowResult =
  | { outcome: 'APPROVED'; grantId: string }
  | { outcome: 'DENIED' }
  | { outcome: 'EXPIRED' };
