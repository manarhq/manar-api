import { GrantTriple } from '../authorization/grant-triples';

/** Thrown when the mTLS-authenticated agent calling `POST /agent/v1/tasks/:id/delegate` is not the task's `assignedAgentId`. */
export class DelegationNotAssignedAgentError extends Error {
  constructor(taskId: string) {
    super(`Caller is not the assigned agent for task "${taskId}"`);
    this.name = 'DelegationNotAssignedAgentError';
  }
}

/** ADR-0009: the delegating agent itself is stopped (quarantine, kill switch, AI-system state). Maps to 403 `{ decision: 'DENY', reason }`. */
export class DelegationDeniedError extends Error {
  constructor(public readonly reason: string) {
    super(`Delegation denied: ${reason}`);
    this.name = 'DelegationDeniedError';
  }
}

/** Thrown when the parent task (or any of its ancestors) is not fully live — a task that can't currently authorize its own actions can't hand out any of them either. */
export class DelegationTaskNotLiveError extends Error {
  constructor(
    taskId: string,
    public readonly reason: string,
  ) {
    super(`Task "${taskId}" is not live enough to delegate from (${reason})`);
    this.name = 'DelegationTaskNotLiveError';
  }
}

/**
 * Thrown when the requested child grants are not a subset of the parent
 * task's *effective* (ancestor-chain-intersected) grant set — Section 20's
 * core non-amplification invariant. The whole delegation is rejected;
 * nothing is ever partially persisted (this error is always thrown before
 * any write — see DelegationService.delegate).
 */
export class DelegationExceedsParentAuthorityError extends Error {
  constructor(public readonly rejectedGrants: GrantTriple[]) {
    super(
      `Requested delegation includes grant(s) the parent task does not itself effectively hold: ${JSON.stringify(rejectedGrants)}`,
    );
    this.name = 'DelegationExceedsParentAuthorityError';
  }
}

/**
 * Thrown when the request asks for a higher `riskCeiling` than the parent
 * task's, or for more executions than the parent has left (including
 * unlimited when the parent is limited). Rejected rather than clamped, like
 * the grant subset check above; omitted values are clamped instead (see
 * DelegationService.delegate). Always thrown before any write.
 */
export class DelegationExceedsParentLimitsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DelegationExceedsParentLimitsError';
  }
}
