import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import {
  ENFORCEMENT_DEPENDENCY_UNAVAILABLE,
  EnforcementDependencyUnavailableException,
  failClosed,
} from './fail-closed';

describe('failClosed', () => {
  it('turns a dependency error into a 503 with the enforcement reason', async () => {
    const error = await failClosed('tenant-db', () =>
      Promise.reject(new Error('ECONNREFUSED')),
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(EnforcementDependencyUnavailableException);
    const exception = error as EnforcementDependencyUnavailableException;
    expect(exception.getStatus()).toBe(503);
    expect(exception.getResponse()).toMatchObject({
      reason: ENFORCEMENT_DEPENDENCY_UNAVAILABLE,
      dependency: 'tenant-db',
    });
  });

  it('passes HTTP decisions through unchanged', async () => {
    const denied = new ForbiddenException('no');
    await expect(
      failClosed('tenant-db', () => Promise.reject(denied)),
    ).rejects.toBe(denied);
  });

  it('returns the value when the dependency answers', async () => {
    await expect(failClosed('x', () => Promise.resolve(7))).resolves.toBe(7);
  });
});
