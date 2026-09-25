import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ThrottlerException } from '@nestjs/throttler';
import type {
  ThrottlerModuleOptions,
  ThrottlerStorage,
} from '@nestjs/throttler';
import { describe, expect, it, vi } from 'vitest';
import { EnforcementDependencyUnavailableException } from '../common/fail-closed/fail-closed';
import { AgentThrottlerGuard } from './agent-throttler.guard';

type StorageRecord = Awaited<ReturnType<ThrottlerStorage['increment']>>;

const OPTIONS: ThrottlerModuleOptions = {
  throttlers: [{ name: 'agent', ttl: 60_000, limit: 1 }],
};

async function setup(increment: ThrottlerStorage['increment']) {
  const response = { header: vi.fn() };
  const context = {
    getType: () => 'http',
    getHandler: () => function handler(): void {},
    getClass: () => class TestController {},
    switchToHttp: () => ({
      getRequest: () => ({
        url: '/agent/v1/tools/invoke',
        ip: '10.0.0.5',
        headers: {},
        raw: { socket: {} },
      }),
      getResponse: () => response,
    }),
  } as unknown as ExecutionContext;
  const guard = new AgentThrottlerGuard(
    OPTIONS,
    { increment },
    new Reflector(),
  );
  await guard.onModuleInit();
  return { guard, context, response };
}

describe('AgentThrottlerGuard (R6: fail closed on the limits store)', () => {
  it('denies with 503 enforcement_dependency_unavailable and Retry-After when storage is down', async () => {
    const { guard, context, response } = await setup(
      vi.fn().mockRejectedValue(new Error('Redis command timed out')),
    );

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      EnforcementDependencyUnavailableException,
    );
    expect(response.header).toHaveBeenCalledWith('Retry-After', '5');
  });

  it('still raises a real 429 when over the limit', async () => {
    const blocked: StorageRecord = {
      totalHits: 2,
      timeToExpire: 60,
      isBlocked: true,
      timeToBlockExpire: 30,
    };
    const { guard, context } = await setup(vi.fn().mockResolvedValue(blocked));

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      ThrottlerException,
    );
  });
});
