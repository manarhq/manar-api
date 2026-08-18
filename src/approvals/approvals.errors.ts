/** Thrown when an `ApprovalRequest` ID doesn't resolve within the caller's tenant database. */
export class ApprovalRequestNotFoundError extends Error {
  constructor(approvalRequestId: string) {
    super(`ApprovalRequest "${approvalRequestId}" was not found`);
    this.name = 'ApprovalRequestNotFoundError';
  }
}

/** Thrown by `POST /approvals/:id/decide` when the request is no longer `PENDING` — a second decision attempt (by the same or a different approver) on an already-resolved request is rejected rather than silently accepted. */
export class ApprovalRequestNotPendingError extends Error {
  constructor(approvalRequestId: string, status: string) {
    super(
      `ApprovalRequest "${approvalRequestId}" is not PENDING (current status: "${status}")`,
    );
    this.name = 'ApprovalRequestNotPendingError';
  }
}
