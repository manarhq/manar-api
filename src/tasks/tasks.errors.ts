/** Thrown when a `Task` ID doesn't resolve within the caller's tenant database. */
export class TaskNotFoundError extends Error {
  constructor(taskId: string) {
    super(`Task "${taskId}" was not found`);
    this.name = 'TaskNotFoundError';
  }
}

/**
 * Fail-closed guard against a malformed/cyclic `parentTaskId` chain: the
 * ancestor walk (Section 20 — every ancestor must be checked, no matter
 * how deep the delegation chain) is bounded rather than infinite. Hitting
 * this is evidence of data corruption (a cycle, which the schema doesn't
 * otherwise prevent), never a legitimate deep chain in practice — treated
 * as a hard failure rather than silently truncating the walk, since a
 * truncated ancestor walk would silently skip a revocation check further
 * up the chain.
 */
export class AncestorChainTooDeepError extends Error {
  constructor(taskId: string, maxDepth: number) {
    super(
      `Task "${taskId}"'s ancestor chain exceeds ${maxDepth} hops — refusing to walk further (likely a cyclic parentTaskId)`,
    );
    this.name = 'AncestorChainTooDeepError';
  }
}
