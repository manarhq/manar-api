import type { ThrottlerStorage } from '@nestjs/throttler';
import { describe, expect, it } from 'vitest';
import { registry } from '../metrics/metrics';
import { LocalFallbackThrottlerStorage } from './local-fallback-throttler-storage';

async function active(): Promise<number | undefined> {
  const m = await registry
    .getSingleMetric('manar_rate_limit_fallback_active')
    ?.get();
  return m?.values.find((v) => v.labels.surface === 'unit')?.value;
}

describe('LocalFallbackThrottlerStorage', () => {
  it('keeps the same limit in memory while Redis fails, then returns to Redis', async () => {
    let redisUp = false;
    const primaryRecord = {
      totalHits: 1,
      timeToExpire: 60,
      isBlocked: false,
      timeToBlockExpire: 0,
    };
    const primary: ThrottlerStorage = {
      increment: () =>
        redisUp
          ? Promise.resolve(primaryRecord)
          : Promise.reject(new Error('ECONNREFUSED')),
    };
    const storage = new LocalFallbackThrottlerStorage(primary, 'unit');

    const hits = [];
    for (let i = 0; i < 3; i++) {
      hits.push(
        await storage.increment('tenant:t1', 60_000, 2, 60_000, 'human'),
      );
    }
    expect(hits.map((h) => h.isBlocked)).toEqual([false, false, true]);
    expect(await active()).toBe(1);

    redisUp = true;
    await expect(
      storage.increment('tenant:t1', 60_000, 2, 60_000, 'human'),
    ).resolves.toBe(primaryRecord);
    expect(await active()).toBe(0);
  });
});
