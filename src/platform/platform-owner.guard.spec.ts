import { ForbiddenException, type ExecutionContext } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { UsageQuerySchema } from '../ai-telemetry/platform-ai-usage.controller';
import { PlatformOwnerGuard } from './platform-owner.guard';

const guard = new PlatformOwnerGuard({
  get: () => 'manar-platform-owner',
} as never);
const ctx = (caller?: { roles?: string[] }) =>
  ({
    switchToHttp: () => ({ getRequest: () => ({ platformCaller: caller }) }),
  }) as unknown as ExecutionContext;

describe('PlatformOwnerGuard (AI cost routes are for Owners only)', () => {
  it('lets a token with the Owner role through', () => {
    expect(
      guard.canActivate(
        ctx({ roles: ['manar-platform-admin', 'manar-platform-owner'] }),
      ),
    ).toBe(true);
  });

  it.each([
    ['only the platform admin role', { roles: ['manar-platform-admin'] }],
    ['no roles recorded', {}],
    ['no caller at all', undefined],
  ])('refuses %s', (_name, caller) => {
    expect(() => guard.canActivate(ctx(caller))).toThrow(ForbiddenException);
  });
});

describe('ai-usage query', () => {
  it('defaults to feature and model, accepts workspace and day, refuses unknown groups and extra keys', () => {
    expect(UsageQuerySchema.parse({}).groupBy).toEqual(['feature', 'model']);
    expect(
      UsageQuerySchema.parse({ groupBy: 'workspace,day' }).groupBy,
    ).toEqual(['workspace', 'day']);
    expect(UsageQuerySchema.safeParse({ groupBy: 'prompt' }).success).toBe(
      false,
    );
    expect(UsageQuerySchema.safeParse({ tenantId: 'x' }).success).toBe(false);
  });
});
