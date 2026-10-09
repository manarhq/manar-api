import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { RedisThrottlerStorageService } from './redis-throttler-storage.service';

function fakeConfigService(
  url = process.env.REDIS_URL ?? 'redis://localhost:6379',
): ConfigService<AppConfig, true> {
  return {
    get: (key: string) => (key === 'RATE_LIMIT_REDIS_TIMEOUT_MS' ? 250 : url),
  } as unknown as ConfigService<AppConfig, true>;
}

/**
 * `RedisThrottlerStorageService.increment`'s Lua script, against a real
 * local Redis (`pnpm infra:up`) — the `@nestjs/throttler`-documented
 * `ThrottlerStorage` contract this class implements. Every test uses its
 * own random key so concurrently-running tests (and other suites sharing
 * the same Redis instance) never interfere with each other.
 */
describe('RedisThrottlerStorageService (real Redis)', () => {
  let service: RedisThrottlerStorageService;

  beforeAll(async () => {
    service = new RedisThrottlerStorageService(fakeConfigService());
    await service.onModuleInit();
  });

  afterAll(async () => {
    await service.onModuleDestroy();
  });

  function uniqueKey(): string {
    return `test-${randomUUID()}`;
  }

  it('the first increment reports totalHits=1 and is never blocked', async () => {
    const result = await service.increment(
      uniqueKey(),
      10_000,
      5,
      10_000,
      'test',
    );
    expect(result.totalHits).toBe(1);
    expect(result.isBlocked).toBe(false);
    expect(result.timeToExpire).toBeGreaterThan(0);
  });

  it('increments totalHits on each call for the same key', async () => {
    const key = uniqueKey();
    const first = await service.increment(key, 10_000, 5, 10_000, 'test');
    const second = await service.increment(key, 10_000, 5, 10_000, 'test');
    const third = await service.increment(key, 10_000, 5, 10_000, 'test');
    expect([first.totalHits, second.totalHits, third.totalHits]).toEqual([
      1, 2, 3,
    ]);
  });

  it('reports isBlocked once totalHits exceeds the limit, and stays blocked on subsequent calls within the block window', async () => {
    const key = uniqueKey();
    const limit = 2;
    let last;
    for (let i = 0; i < limit; i += 1) {
      last = await service.increment(key, 10_000, limit, 5_000, 'test');
      expect(last.isBlocked).toBe(false);
    }
    // The (limit + 1)th call exceeds the limit.
    const overLimit = await service.increment(
      key,
      10_000,
      limit,
      5_000,
      'test',
    );
    expect(overLimit.isBlocked).toBe(true);
    expect(overLimit.timeToBlockExpire).toBeGreaterThan(0);

    // Still blocked on a further call, within the block window.
    const stillBlocked = await service.increment(
      key,
      10_000,
      limit,
      5_000,
      'test',
    );
    expect(stillBlocked.isBlocked).toBe(true);
  });

  it('two different keys never share a counter (tenant/agent partitioning at the storage layer)', async () => {
    const keyA = uniqueKey();
    const keyB = uniqueKey();
    await service.increment(keyA, 10_000, 2, 10_000, 'test');
    await service.increment(keyA, 10_000, 2, 10_000, 'test');
    const blockedA = await service.increment(keyA, 10_000, 2, 10_000, 'test');
    expect(blockedA.isBlocked).toBe(true);

    // keyB's own first hit is unaffected by keyA's block.
    const freshB = await service.increment(keyB, 10_000, 2, 10_000, 'test');
    expect(freshB.isBlocked).toBe(false);
    expect(freshB.totalHits).toBe(1);
  });

  it('the block expires after blockDuration elapses, and a subsequent call is no longer blocked', async () => {
    const key = uniqueKey();
    const limit = 1;
    const blockDurationMs = 300;
    await service.increment(key, 10_000, limit, blockDurationMs, 'test'); // 1st, not blocked
    const blocked = await service.increment(
      key,
      10_000,
      limit,
      blockDurationMs,
      'test',
    ); // 2nd, exceeds limit
    expect(blocked.isBlocked).toBe(true);

    await new Promise((resolve) => setTimeout(resolve, blockDurationMs + 200));

    const afterBlockExpires = await service.increment(
      key,
      10_000,
      limit,
      blockDurationMs,
      'test',
    );
    expect(afterBlockExpires.isBlocked).toBe(false);
  }, 10_000);
});
