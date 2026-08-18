/** Thrown when an `Agent` ID/slug doesn't resolve within the caller's tenant database. */
export class AgentNotFoundError extends Error {
  constructor(agentId: string) {
    super(`Agent "${agentId}" was not found`);
    this.name = 'AgentNotFoundError';
  }
}

/**
 * Thrown by `AgentsService.enroll` for any reason an enrollment token isn't
 * usable right now: unknown (hash doesn't match any stored token — covers
 * both a genuinely bogus token and one that never existed), already used
 * (single-use, Section 14 — a second attempt fails even if the token
 * somehow leaked), or expired (short TTL — see
 * `AgentsService.ENROLLMENT_TOKEN_TTL_MS`). Deliberately one error type
 * with a distinguishing `reason`, not three: the HTTP response is the same
 * either way (400/401, no detail about *why* to an unauthenticated
 * caller — distinguishing them would let an attacker probe which
 * tokens/agents exist).
 */
export class EnrollmentTokenInvalidError extends Error {
  constructor(public readonly reason: 'not_found' | 'used' | 'expired') {
    super(`Enrollment token is not usable (${reason})`);
    this.name = 'EnrollmentTokenInvalidError';
  }
}
