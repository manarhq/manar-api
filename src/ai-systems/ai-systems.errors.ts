/**
 * Release 2026-11-11 — `AiSystemsService`'s typed domain errors, mapped to
 * HTTP by `AiSystemsController.mapAiSystemErrors` (the same convention
 * `IncidentsController`/`UsersController` already use — a service never
 * imports `@nestjs/common`'s HTTP exceptions).
 */

/** Thrown when an `AiSystem` ID or slug doesn't resolve within the caller's tenant database. */
export class AiSystemNotFoundError extends Error {
  constructor(identifier: string) {
    super(`AI system "${identifier}" was not found`);
    this.name = 'AiSystemNotFoundError';
  }
}

/** Thrown when a create/update would collide with an existing `AiSystem.slug`. */
export class AiSystemSlugConflictError extends Error {
  constructor(slug: string) {
    super(`An AI system with slug "${slug}" already exists`);
    this.name = 'AiSystemSlugConflictError';
  }
}

/**
 * Thrown when a requested lifecycle transition is not an edge in
 * `ALLOWED_TRANSITIONS`. Carries both states so the HTTP layer can render
 * a message an operator can act on rather than a bare 409.
 */
export class AiSystemInvalidTransitionError extends Error {
  constructor(
    readonly fromState: string,
    readonly toState: string,
  ) {
    super(
      `Lifecycle transition ${fromState} -> ${toState} is not allowed. See docs/release/2026-11-11/ai-system-inventory.md for the permitted edges.`,
    );
    this.name = 'AiSystemInvalidTransitionError';
  }
}

/**
 * Thrown when the caller is the same person who performed the transition
 * that the requested one is meant to independently review — see
 * `AiSystemsService.transitionState`'s separation-of-duties check. A
 * distinct error type (not a generic 403) because the remedy is specific:
 * a *different* authorized reviewer must perform this transition.
 */
export class AiSystemSeparationOfDutiesError extends Error {
  constructor(readonly toState: string) {
    super(
      `Transition to ${toState} must be performed by a different user than the one who submitted this AI system for review`,
    );
    this.name = 'AiSystemSeparationOfDutiesError';
  }
}

/** Thrown when a referenced `UserProfile` (an owner), `Agent`, or `Tool` doesn't exist in the caller's tenant database. */
export class AiSystemReferenceNotFoundError extends Error {
  constructor(
    readonly kind: 'owner' | 'agent' | 'tool',
    readonly id: string,
  ) {
    super(`Referenced ${kind} "${id}" was not found in this tenant`);
    this.name = 'AiSystemReferenceNotFoundError';
  }
}

/** Thrown when a mutation is attempted on a `RETIRED` system — the one terminal state. */
export class AiSystemRetiredError extends Error {
  constructor(aiSystemId: string) {
    super(
      `AI system "${aiSystemId}" is RETIRED and can no longer be modified. Retirement is deliberately terminal so a retired system's evidence trail stays fixed.`,
    );
    this.name = 'AiSystemRetiredError';
  }
}
