import {
  HttpException,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { getCorrelationId } from '../../logging/correlation-id.store';

export const ENFORCEMENT_DEPENDENCY_UNAVAILABLE =
  'enforcement_dependency_unavailable';

/**
 * A dependency the enforcement path needs (identity, tenant resolution,
 * revocation lookup, kill-switch state, limits store, grant store) failed.
 * The request is denied with 503 and a stable reason code, never a bare 500
 * and never an ALLOW (`CLAUDE.md`: fail closed).
 */
export class EnforcementDependencyUnavailableException extends ServiceUnavailableException {
  /** `message`, when given, is shown to a person, with the request's correlation id as `reference`. */
  constructor(
    readonly dependency: string,
    message?: string,
  ) {
    const reference = message === undefined ? undefined : getCorrelationId();
    super({
      statusCode: 503,
      error: 'Service Unavailable',
      reason: ENFORCEMENT_DEPENDENCY_UNAVAILABLE,
      dependency,
      ...(message === undefined ? {} : { message }),
      ...(reference === undefined ? {} : { reference }),
    });
  }
}

const logger = new Logger('FailClosed');

/**
 * Rethrows `error` if it is already an HTTP decision (401, 403, 404, 429,
 * ...); otherwise logs the message (never payloads or tokens) and throws
 * `EnforcementDependencyUnavailableException`.
 */
export function throwFailClosed(dependency: string, error: unknown): never {
  if (error instanceof HttpException) throw error;
  logger.error(
    `${dependency} unavailable, denying: ${error instanceof Error ? error.message : String(error)}`,
  );
  throw new EnforcementDependencyUnavailableException(dependency);
}

/** Runs `fn`, turning any non-HTTP failure into a fail-closed 503. */
export async function failClosed<T>(
  dependency: string,
  fn: () => Promise<T>,
): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    throwFailClosed(dependency, error);
  }
}
