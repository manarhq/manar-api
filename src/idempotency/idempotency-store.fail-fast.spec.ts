import { createServer, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';
import type { ConfigService } from '@nestjs/config';
import { describe, expect, it } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import { IdempotencyStoreService } from './idempotency-store.service';

/** Review finding (9 Oct): the idempotency store's Redis client had no bounds. */
describe('IdempotencyStoreService is bounded when Redis does not answer', () => {
  it('claim rejects within REDIS_TIMEOUT_MS instead of hanging', async () => {
    const sockets: Socket[] = [];
    const blackHole = createServer((s) => sockets.push(s));
    await new Promise<void>((r) => blackHole.listen(0, '127.0.0.1', r));
    const { port } = blackHole.address() as AddressInfo;
    const store = new IdempotencyStoreService({
      get: (key: string) =>
        key === 'REDIS_TIMEOUT_MS' ? 250 : `redis://127.0.0.1:${port}`,
    } as unknown as ConfigService<AppConfig, true>);

    const started = Date.now();
    const outcome = await Promise.race([
      store.claim('k', 60_000).then(
        () => 'resolved',
        () => 'rejected',
      ),
      new Promise((r) => setTimeout(() => r('hung'), 3_000)),
    ]);
    expect(outcome).toBe('rejected');
    expect(Date.now() - started).toBeLessThan(1_000);

    await store.onModuleDestroy();
    sockets.forEach((s) => s.destroy());
    blackHole.close();
  });
});
