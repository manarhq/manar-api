/** Thrown when a `Policy` ID doesn't resolve within the caller's tenant database. */
export class PolicyNotFoundError extends Error {
  constructor(policyId: string) {
    super(`Policy "${policyId}" was not found`);
    this.name = 'PolicyNotFoundError';
  }
}

/** Thrown when a `PolicyVersion` ID doesn't resolve for the given policy within the caller's tenant database. */
export class PolicyVersionNotFoundError extends Error {
  constructor(policyId: string, versionId: string) {
    super(
      `Policy version "${versionId}" was not found for policy "${policyId}"`,
    );
    this.name = 'PolicyVersionNotFoundError';
  }
}

/**
 * Thrown by `PolicyService.publishVersion` when the target version is not
 * `DRAFT` — publishing is only ever a DRAFT -> PUBLISHED transition, never
 * re-publishing an already-`PUBLISHED` version (which is immutable — see
 * `PolicyVersion`'s schema doc comment) and never anything else.
 */
export class PolicyVersionNotDraftError extends Error {
  constructor(versionId: string, actualStatus: string) {
    super(
      `Policy version "${versionId}" cannot be published — its status is "${actualStatus}", not "DRAFT"`,
    );
    this.name = 'PolicyVersionNotDraftError';
  }
}
