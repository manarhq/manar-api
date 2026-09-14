import { HttpException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ThrottlerException } from '@nestjs/throttler';
import type {
  ThrottlerModuleOptions,
  ThrottlerStorage,
} from '@nestjs/throttler';
import { describe, expect, it, vi } from 'vitest';
import type { KnownIssuerRegistry } from '../auth/known-issuer-registry.service';
import { TenantThrottlerGuard } from './tenant-throttler.guard';

/**
 * The two release-2026-11-11 behaviours this guard grew, both of which
 * exist because it is a **global** `APP_GUARD` and therefore runs on every
 * route in the application:
 *
 * 1. The kubelet's probe paths are exempt. Without that, a Redis outage
 *    made `/health/live` return 500 (@nestjs/throttler 6.5.0 calls
 *    `ThrottlerStorage.increment` unguarded, and
 *    `RedisThrottlerStorageService` throws when Redis is unreachable), and
 *    the kubelet restarted every replica in the Deployment.
 * 2. A storage failure fails **open** rather than 500ing the request — but
 *    a genuine over-limit `ThrottlerException` is still thrown, so
 *    enforcement is unchanged whenever the storage is healthy. See the
 *    guard's own doc comment and
 *    docs/release/2026-11-11/fix-notes-reliability.md for the security
 *    reasoning behind that choice.
 *
 * Collaborators are plain in-memory fakes, no Nest DI container — same
 * house style as `jwt-auth.guard.spec.ts`.
 */

const THROTTLER_OPTIONS: ThrottlerModuleOptions = {
  throttlers: [{ name: 'human', ttl: 60_000, limit: 100 }],
};

/**
 * `@nestjs/throttler` 6.5.0 does not export its `ThrottlerStorageRecord`
 * type, so this mirrors the shape the same way
 * `redis-throttler-storage.service.ts` already does.
 */
type StorageRecord = Awaited<ReturnType<ThrottlerStorage['increment']>>;

const ALLOWED: StorageRecord = {
  totalHits: 1,
  timeToExpire: 60,
  isBlocked: false,
  timeToBlockExpire: 0,
};

const BLOCKED: StorageRecord = {
  totalHits: 101,
  timeToExpire: 60,
  isBlocked: true,
  timeToBlockExpire: 30,
};

function makeContext(url: string): ExecutionContext {
  const request = { url, ip: '10.0.0.1', headers: {} };
  const response = { header: vi.fn() };

  return {
    getType: () => 'http',
    getHandler: () => function handler(): void {},
    getClass: () => class TestController {},
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => response,
    }),
  } as unknown as ExecutionContext;
}

async function makeGuard(
  increment: ThrottlerStorage['increment'],
): Promise<{ guard: TenantThrottlerGuard }> {
  const storage = { increment };

  const knownIssuerRegistry = {
    resolveByIssuer: () => Promise.resolve(null),
  } as unknown as KnownIssuerRegistry;

  const guard = new TenantThrottlerGuard(
    THROTTLER_OPTIONS,
    storage,
    new Reflector(),
    knownIssuerRegistry,
  );
  // The base class resolves its throttler list here; `canActivate` reads it.
  await guard.onModuleInit();

  return { guard };
}

describe('TenantThrottlerGuard health-route exemption', () => {
  it.each([
    '/health/live',
    '/health/ready',
    '/health/ready?verbose=1',
    '/health/live/',
  ])('never touches rate-limit storage for %s', async (url) => {
    const increment = vi.fn().mockRejectedValue(new Error('Redis is down'));
    const { guard } = await makeGuard(increment);

    // The regression this pins: with Redis down, the probe still answers.
    await expect(guard.canActivate(makeContext(url))).resolves.toBe(true);
    expect(increment).not.toHaveBeenCalled();
  });

  it.each(['/healthcheck-proxy', '/tenants/health', '/health-report'])(
    'does not hand a rate-limit exemption to look-alike path %s',
    async (url) => {
      const increment = vi.fn().mockResolvedValue(ALLOWED);
      const { guard } = await makeGuard(increment);

      await expect(guard.canActivate(makeContext(url))).resolves.toBe(true);
      expect(increment).toHaveBeenCalledTimes(1);
    },
  );
});

describe('TenantThrottlerGuard storage failure handling', () => {
  it('fails open when the rate-limit storage is unavailable', async () => {
    const increment = vi
      .fn()
      .mockRejectedValue(
        new Error('Redis throttler storage: no connection available'),
      );
    const { guard } = await makeGuard(increment);

    // Rate limiting is availability protection, not an authorization
    // control — every real auth guard runs after this one and is untouched.
    await expect(guard.canActivate(makeContext('/tasks'))).resolves.toBe(true);
    expect(increment).toHaveBeenCalledTimes(1);
  });

  it('still enforces the limit — a 429 is never swallowed by the fail-open catch', async () => {
    const increment = vi.fn().mockResolvedValue(BLOCKED);
    const { guard } = await makeGuard(increment);

    await expect(guard.canActivate(makeContext('/tasks'))).rejects.toThrow(
      ThrottlerException,
    );
  });

  it('re-throws any HttpException raised by the throttling pipeline rather than failing open', async () => {
    const increment = vi.fn().mockImplementation(() => {
      throw new HttpException('deliberate', 418);
    });
    const { guard } = await makeGuard(increment);

    await expect(guard.canActivate(makeContext('/tasks'))).rejects.toThrow(
      HttpException,
    );
  });

  it('allows a normal, under-limit request when storage is healthy', async () => {
    const increment = vi.fn().mockResolvedValue(ALLOWED);
    const { guard } = await makeGuard(increment);

    await expect(guard.canActivate(makeContext('/tasks'))).resolves.toBe(true);
    expect(increment).toHaveBeenCalledTimes(1);
  });
});
