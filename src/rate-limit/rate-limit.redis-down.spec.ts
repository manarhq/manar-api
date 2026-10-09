import { createServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { Controller, Get, UseGuards } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { Test } from '@nestjs/testing';
import {
  ThrottlerGuard,
  ThrottlerModule,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AppConfig } from '../config/env.validation';
import { registry } from '../metrics/metrics';
import { AgentThrottlerGuard } from './agent-throttler.guard';
import { LocalFallbackThrottlerStorage } from './local-fallback-throttler-storage';
import { RedisThrottlerStorageService } from './redis-throttler-storage.service';

/**
 * Security review of the fail-fast change (9 Oct): with Redis down, the
 * human surface must stay rate limited (in-memory fallback, never
 * unlimited) and the agent surface must still fail closed, fast.
 */
@Controller()
class HumanController {
  @Get('human')
  @UseGuards(ThrottlerGuard)
  ping() {
    return { ok: true };
  }
}

@Controller()
class AgentController {
  @Get('agent')
  @UseGuards(AgentThrottlerGuard)
  ping() {
    return { ok: true };
  }
}

async function closedPort(): Promise<number> {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address() as AddressInfo;
  await new Promise((r) => s.close(r));
  return port;
}

async function appWith(
  storage: ThrottlerStorage,
  name: string,
  controller: new () => unknown,
): Promise<NestFastifyApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [
      ThrottlerModule.forRoot({
        storage,
        throttlers: [{ name, ttl: 60_000, limit: 2 }],
      }),
    ],
    controllers: [controller],
  }).compile();
  const app = moduleRef.createNestApplication<NestFastifyApplication>(
    new FastifyAdapter(),
  );
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
  return app;
}

describe('rate limiting with Redis down', () => {
  let redisDown: RedisThrottlerStorageService;
  let human: NestFastifyApplication;
  let agent: NestFastifyApplication;

  beforeAll(async () => {
    const port = await closedPort();
    redisDown = new RedisThrottlerStorageService({
      get: (key: string) =>
        key === 'REDIS_TIMEOUT_MS' ? 1000 : `redis://127.0.0.1:${port}`,
    } as unknown as ConfigService<AppConfig, true>);
    human = await appWith(
      new LocalFallbackThrottlerStorage(redisDown, 'human'),
      'human',
      HumanController,
    );
    agent = await appWith(redisDown, 'agent', AgentController);
  });

  afterAll(async () => {
    await human.close();
    await agent.close();
    await redisDown.onModuleDestroy();
  });

  it('the human surface stays limited by the in-memory fallback', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) {
      statuses.push(
        (await human.inject({ method: 'GET', url: '/human' })).statusCode,
      );
    }
    expect(statuses).toEqual([200, 200, 429]);
    expect(await registry.metrics()).toMatch(
      /manar_rate_limit_fallback_active\{[^}]*surface="human"[^}]*\} 1/,
    );
  });

  it('the agent surface fails closed with a 503, fast', async () => {
    const started = Date.now();
    const res = await agent.inject({ method: 'GET', url: '/agent' });
    expect(res.statusCode).toBe(503);
    expect(res.body).toContain('enforcement_dependency_unavailable');
    expect(Date.now() - started).toBeLessThan(1500);
  });
});
