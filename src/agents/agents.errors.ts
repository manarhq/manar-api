/** Thrown when an `Agent` ID/slug doesn't resolve within the caller's tenant database. */
export class AgentNotFoundError extends Error {
  constructor(agentId: string) {
    super(`Agent "${agentId}" was not found`);
    this.name = 'AgentNotFoundError';
  }
}

/** Thrown when an enrollment token is requested for a `REVOKED` or `KILLED` agent (Gate 0 R4): both states are terminal, and re-enrolment would undo the revocation. */
export class AgentTerminatedError extends Error {
  constructor(
    agentId: string,
    public readonly status: string,
  ) {
    super(`Agent "${agentId}" is ${status} and cannot be re-enrolled`);
    this.name = 'AgentTerminatedError';
  }
}

export type EnrollmentFailureReason =
  'not_found' | 'used' | 'expired' | 'agent_terminated';

/**
 * Thrown by `AgentsService.enroll` for any reason an enrollment token isn't
 * usable right now: unknown (hash doesn't match any stored token — covers
 * both a genuinely bogus token and one that never existed), already used
 * (single-use, Section 14 — a second attempt fails even if the token
 * somehow leaked), expired (short TTL — see
 * `AgentsService.ENROLLMENT_TOKEN_TTL_MS`), or minted for an agent that has
 * since been revoked or killed (`agent_terminated`). Deliberately one error
 * type with a distinguishing `reason`: the HTTP response is the same
 * either way (400/401, no detail about *why* to an unauthenticated
 * caller — distinguishing them would let an attacker probe which
 * tokens/agents exist).
 */
export class EnrollmentTokenInvalidError extends Error {
  constructor(public readonly reason: EnrollmentFailureReason) {
    super(`Enrollment token is not usable (${reason})`);
    this.name = 'EnrollmentTokenInvalidError';
  }
}
