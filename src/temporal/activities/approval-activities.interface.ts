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
  status: 'APPROVED' | 'DENIED' | 'EXPIRED';
  /** Present only when `status` is `APPROVED`. */
  grantId?: string;
}

export interface ExpireApprovalRequestInput {
  tenantId: string;
  approvalRequestId: string;
}

export interface AttachRiskAdvisoryInput {
  tenantId: string;
  approvalRequestId: string;
}

export interface ApprovalActivities {
  /**
   * Phase 1 (ADR-004). Fetches manar-ai's risk advisory and attaches it to the
   * ApprovalRequest **for the human approver**.
   *
   * This exists because the advisory used to be a decision input —
   * `RiskEngine` awaited it and folded it in as
   * `max(deterministic, advisory ?? 0)`, putting a language model inside the
   * authorization decision. ADR-004 and CLAUDE.md §12 forbid that. Running it
   * here instead keeps it off the synchronous decision path while preserving
   * what CLAUDE.md §5.1 actually licenses: an advisory signal *attached to* a
   * deterministic decision.
   *
   * Never affects the outcome. The decision was already made, durably, before
   * this workflow started. On any failure — manar-ai down, circuit open,
   * timeout, zero-confidence fail-secure marker — the approval keeps
   * `advisoryUnavailable = true` and the human decides without it. That is the
   * `CLAUDE.md` §6 row: "manar-ai unavailable → continue deterministic path;
   * advisory_unavailable = true on the record".
   *
   * Idempotent: re-running overwrites the same columns with the same result.
   */
  attachRiskAdvisory(input: AttachRiskAdvisoryInput): Promise<void>;

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
