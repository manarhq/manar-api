import { createServer, connect, type Server, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { RedisThrottlerStorageService } from './redis-throttler-storage.service';

/**
 * Load-test finding (9 Oct): with Redis down, every agent request waited
 * about 5 s before failing closed. Failing closed must also be fast: each
 * limits-store call is bounded by RATE_LIMIT_REDIS_TIMEOUT_MS.
 */
const TIMEOUT_MS = 250;
const BOUND_MS = 1_000;
const REDIS = new URL(process.env.REDIS_URL ?? 'redis://localhost:6379');

function config(url: string): ConfigService<AppConfig, true> {
  return {
    get: (key: string) =>
      key === 'RATE_LIMIT_REDIS_TIMEOUT_MS' ? TIMEOUT_MS : url,
  } as unknown as ConfigService<AppConfig, true>;
}

/** Elapsed ms until `work` settles; never waits more than 3 s. */
async function timeToReject(work: () => Promise<unknown>): Promise<number> {
  const started = Date.now();
  const outcome = await Promise.race([
    work().then(
      () => 'resolved',
      () => 'rejected',
    ),
    new Promise((r) => setTimeout(() => r('hung'), 3_000)),
  ]);
  expect(outcome).toBe('rejected');
  return Date.now() - started;
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve((server.address() as AddressInfo).port),
    ),
  );
}

describe('RedisThrottlerStorageService fails fast when Redis is unavailable', () => {
  const servers: Server[] = [];
  const services: RedisThrottlerStorageService[] = [];
  afterEach(async () => {
    for (const s of services.splice(0)) await s.onModuleDestroy();
    for (const s of servers.splice(0)) s.close();
  });

  it('a Redis that accepts but never answers is bounded', async () => {
    const sockets: Socket[] = [];
    const blackHole = createServer((socket) => sockets.push(socket));
    servers.push(blackHole);
    const port = await listen(blackHole);
    const service = new RedisThrottlerStorageService(
      config(`redis://127.0.0.1:${port}`),
    );
    services.push(service);

    const ms = await timeToReject(() =>
      service.increment('k', 60_000, 10, 60_000, 'agent'),
    );
    expect(ms).toBeLessThan(BOUND_MS);
    sockets.forEach((s) => s.destroy());
  });

  it('Redis going away under a live connection is bounded, and recovers', async () => {
    // A proxy to the real Redis that can be cut, like a crashed primary.
    const sockets: Socket[] = [];
    const makeProxy = () =>
      createServer((client) => {
        const upstream = connect(Number(REDIS.port || 6379), REDIS.hostname);
        sockets.push(client, upstream);
        client.pipe(upstream).pipe(client);
        client.on('error', () => upstream.destroy());
        upstream.on('error', () => client.destroy());
      });
    const proxy = makeProxy();
    servers.push(proxy);
    const port = await listen(proxy);
    const service = new RedisThrottlerStorageService(
      config(`redis://127.0.0.1:${port}`),
    );
    services.push(service);
    await service.onModuleInit();
    await expect(
      service.increment(`fail-fast-${port}`, 60_000, 10, 60_000, 'agent'),
    ).resolves.toMatchObject({ totalHits: 1 });

    proxy.close();
    sockets.forEach((s) => s.destroy());
    for (let i = 0; i < 3; i++) {
      const ms = await timeToReject(() =>
        service.increment(`fail-fast-${port}`, 60_000, 10, 60_000, 'agent'),
      );
      expect(ms).toBeLessThan(BOUND_MS);
    }

    // Redis is back: the client reconnects and limits apply again.
    const restored = makeProxy();
    servers.push(restored);
    await new Promise<void>((r) => restored.listen(port, '127.0.0.1', r));
    let recovered = false;
    for (let i = 0; i < 40 && !recovered; i++) {
      recovered = await service
        .increment(`fail-fast-${port}`, 60_000, 10, 60_000, 'agent')
        .then(
          () => true,
          () => false,
        );
      if (!recovered) await new Promise((r) => setTimeout(r, 100));
    }
    expect(recovered).toBe(true);
  });
});
