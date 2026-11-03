import { ConflictException } from '@nestjs/common';

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

/**
 * Why an approval action could not be applied. The console maps each to a plain sentence (E-021:
 * a pause used to read as "already decided" because the reason was lost).
 */
export type ApprovalConflictReason =
  | 'paused'
  | 'already_decided'
  | 'expired'
  | 'revoked'
  | 'not_approved'
  | 'action_already_used'
  | 'not_signaled';

/** 409 with a stable `reason` next to the plain `message`. */
export function approvalConflict(
  reason: ApprovalConflictReason,
  message: string,
): ConflictException {
  return new ConflictException({
    statusCode: 409,
    error: 'Conflict',
    reason,
    message,
  });
}

/** The 409 for a request that is no longer PENDING, worded by what it became. */
export function notPendingConflict(status: string): ConflictException {
  if (status === 'EXPIRED')
    return approvalConflict(
      'expired',
      'This request expired before your answer arrived. Nothing was changed.',
    );
  if (status === 'REVOKED')
    return approvalConflict(
      'revoked',
      'This approval was revoked. Nothing was changed.',
    );
  return approvalConflict(
    'already_decided',
    'Someone already answered this request. Nothing was changed.',
  );
}

export const PAUSED_CONFLICT_MESSAGE =
  'AI is paused for this workspace, so nothing can be approved. Resume AI first, or deny the request.';
