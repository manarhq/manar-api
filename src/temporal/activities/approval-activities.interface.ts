/**
 * The Activity contract `ApprovalWorkflow` calls through
 * (`proxyActivities<ApprovalActivities>(...)`). A pure type — imported by
 * the workflow file via `import type` only, so it's erased entirely from
 * the workflow's compiled bundle (Section 28: workflow code contains no
 * I/O; every real implementation of this interface, in
 * `approval.activities.ts`, is Nest/Prisma/crypto code that runs only in
 * the separate worker process — see src/worker.main.ts).
 */

export interface FinalizeApprovalDecisionInput {
  tenantId: string;
  approvalRequestId: string;
  decision: 'APPROVE' | 'DENY';
  approverId: string;
  reason?: string;
}

export interface FinalizeApprovalDecisionResult {
  status: 'APPROVED' | 'DENIED';
  /** Present only when `status` is `APPROVED`. */
  grantId?: string;
}

export interface ExpireApprovalRequestInput {
  tenantId: string;
  approvalRequestId: string;
}

export interface ApprovalActivities {
  /**
   * Runs on both an `APPROVE` and a `DENY` signal (Section 27/28's "an
   * Activity", not workflow code, does the re-evaluation and any DB
   * write). Records the human's raw `ApprovalDecision`, then — only for
   * `APPROVE` — re-evaluates task/agent liveness and re-runs
   * `PolicyEngine`/`RiskEngine` against *current* state before ever
   * issuing an `AuthorizationGrant`. Idempotent: safe to retry (Temporal's
   * own Activity retry policy) without creating a second
   * `ApprovalDecision`/`AuthorizationGrant` for the same request.
   */
  finalizeApprovalDecision(
    input: FinalizeApprovalDecisionInput,
  ): Promise<FinalizeApprovalDecisionResult>;

  /**
   * Runs only when nobody signals `decide` before `ApprovalRequest.expiresAt`
   * — sets `status = EXPIRED`. No `ApprovalDecision` row (nobody decided)
   * and no `AuthorizationGrant` is ever issuable for this request again.
   * Idempotent, same reason as `finalizeApprovalDecision`.
   */
  expireApprovalRequest(input: ExpireApprovalRequestInput): Promise<void>;
}
