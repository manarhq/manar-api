import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { RedisThrottlerStorageService } from './redis-throttler-storage.service';

function fakeConfigService(
  url = process.env.REDIS_URL ?? 'redis://localhost:6379',
): ConfigService<AppConfig, true> {
  return {
    get: (key: string) =>
      key === 'REDIS_TIMEOUT_MS' ? 250 : key === 'REDIS_URL' ? url : undefined,
  } as unknown as ConfigService<AppConfig, true>;
}

/**
 * `RedisThrottlerStorageService.increment`'s GCRA script (spec 7.3), against a real
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

  it('blocks request limit+1 of a burst and reports how long to wait', async () => {
    const key = uniqueKey();
    const limit = 2;
    for (let i = 0; i < limit; i += 1) {
      const ok = await service.increment(key, 10_000, limit, 5_000, 'test');
      expect(ok.isBlocked).toBe(false);
    }
    const over = await service.increment(key, 10_000, limit, 5_000, 'test');
    expect(over.isBlocked).toBe(true);
    expect(over.totalHits).toBe(limit + 1);
    expect(over.timeToBlockExpire).toBeGreaterThan(0);
    // A denied check changes nothing: it stays blocked, the wait does not grow.
    const again = await service.increment(key, 10_000, limit, 5_000, 'test');
    expect(again.isBlocked).toBe(true);
    expect(again.timeToBlockExpire).toBeLessThanOrEqual(over.timeToBlockExpire);
  });

  it('two different keys never share a counter (tenant/agent partitioning at the storage layer)', async () => {
    const keyA = uniqueKey();
    const keyB = uniqueKey();
    await service.increment(keyA, 10_000, 2, 10_000, 'test');
    await service.increment(keyA, 10_000, 2, 10_000, 'test');
    const blockedA = await service.increment(keyA, 10_000, 2, 10_000, 'test');
    expect(blockedA.isBlocked).toBe(true);

    const freshB = await service.increment(keyB, 10_000, 2, 10_000, 'test');
    expect(freshB.isBlocked).toBe(false);
    expect(freshB.totalHits).toBe(1);
  });

  it('the same key under another throttler name is a separate limit', async () => {
    const key = uniqueKey();
    await service.increment(key, 10_000, 1, 10_000, 'human');
    const blocked = await service.increment(key, 10_000, 1, 10_000, 'human');
    expect(blocked.isBlocked).toBe(true);
    const other = await service.increment(key, 10_000, 1, 10_000, 'agent');
    expect(other.isBlocked).toBe(false);
  });

  it('a caller that went over stays blocked for blockDuration even once a slot has refilled', async () => {
    const key = uniqueKey();
    // 3 per 300 ms (a slot every 100 ms), 800 ms block.
    for (let i = 0; i < 3; i += 1) {
      await service.increment(key, 300, 3, 800, 'test');
    }
    expect((await service.increment(key, 300, 3, 800, 'test')).isBlocked).toBe(
      true,
    );
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect((await service.increment(key, 300, 3, 800, 'test')).isBlocked).toBe(
      true,
    );
    await new Promise((resolve) => setTimeout(resolve, 600));
    expect((await service.increment(key, 300, 3, 800, 'test')).isBlocked).toBe(
      false,
    );
  }, 10_000);

  it('recovers after one emission interval (rate is limit per window, not a window cliff)', async () => {
    const key = uniqueKey();
    // limit 2 per 600 ms: one slot every 300 ms.
    await service.increment(key, 600, 2, 0, 'test');
    await service.increment(key, 600, 2, 0, 'test');
    const blocked = await service.increment(key, 600, 2, 0, 'test');
    expect(blocked.isBlocked).toBe(true);

    await new Promise((resolve) => setTimeout(resolve, 400));

    const admitted = await service.increment(key, 600, 2, 0, 'test');
    expect(admitted.isBlocked).toBe(false);
    const again = await service.increment(key, 600, 2, 0, 'test');
    expect(again.isBlocked).toBe(true); // only one slot had refilled
  }, 10_000);

  it('Valkey unreachable: increment rejects, never reports an allowance', async () => {
    const down = new RedisThrottlerStorageService(
      fakeConfigService('redis://127.0.0.1:1'),
    );
    await expect(
      down.increment(uniqueKey(), 10_000, 5, 10_000, 'test'),
    ).rejects.toThrow();
    await down.onModuleDestroy();
  });
});
