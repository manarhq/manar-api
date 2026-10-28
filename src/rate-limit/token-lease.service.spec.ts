import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { TokenLeaseService } from './token-lease.service';

function config(
  url = process.env.REDIS_URL ?? 'redis://localhost:6379',
): ConfigService<AppConfig, true> {
  return {
    get: (key: string) =>
      key === 'REDIS_TIMEOUT_MS' ? 250 : key === 'REDIS_URL' ? url : undefined,
  } as unknown as ConfigService<AppConfig, true>;
}

/** Spec 7.3: LLM token budgets are leased in blocks. Real Valkey (`pnpm infra:up`). */
describe('TokenLeaseService (real Valkey)', () => {
  let svc: TokenLeaseService;
  beforeAll(async () => {
    svc = new TokenLeaseService(config());
    await svc.onModuleInit();
  });
  afterAll(() => svc.onModuleDestroy());

  const tenant = () => `t-${randomUUID()}`;

  it('grants a block, then only what remains', async () => {
    const t = tenant();
    await svc.setBudget(t, 'llm', 120_000);
    expect(await svc.lease(t, 'llm', 'l1', 50_000)).toBe(50_000);
    expect(await svc.lease(t, 'llm', 'l2', 50_000)).toBe(50_000);
    expect(await svc.lease(t, 'llm', 'l3', 50_000)).toBe(20_000);
    expect(await svc.lease(t, 'llm', 'l4', 50_000)).toBe(0);
    expect(await svc.remaining(t, 'llm')).toBe(0);
  });

  it('concurrent leases never hand out more than the budget', async () => {
    const t = tenant();
    await svc.setBudget(t, 'llm', 1000);
    const grants = await Promise.all(
      Array.from({ length: 40 }, (_, i) => svc.lease(t, 'llm', `l${i}`, 100)),
    );
    expect(grants.reduce((a, b) => a + b, 0)).toBe(1000);
  });

  it('a retried lease id returns the same grant and takes nothing more', async () => {
    const t = tenant();
    await svc.setBudget(t, 'llm', 1000);
    expect(await svc.lease(t, 'llm', 'l1', 400)).toBe(400);
    expect(await svc.lease(t, 'llm', 'l1', 400)).toBe(400);
    expect(await svc.remaining(t, 'llm')).toBe(600);
  });

  it('release returns the unspent part once, never more than was granted', async () => {
    const t = tenant();
    await svc.setBudget(t, 'llm', 1000);
    await svc.lease(t, 'llm', 'l1', 400);
    expect(await svc.release(t, 'llm', 'l1', 150)).toBe(150);
    expect(await svc.release(t, 'llm', 'l1', 150)).toBe(0); // second release: nothing
    expect(await svc.remaining(t, 'llm')).toBe(750);
    await svc.lease(t, 'llm', 'l2', 100);
    expect(await svc.release(t, 'llm', 'l2', 9_999)).toBe(100); // capped at the grant
    expect(await svc.remaining(t, 'llm')).toBe(750);
  });

  it('a release for a lease that never existed or expired returns nothing', async () => {
    const t = tenant();
    await svc.setBudget(t, 'llm', 1000);
    expect(await svc.release(t, 'llm', 'ghost', 500)).toBe(0);
    expect(await svc.remaining(t, 'llm')).toBe(1000);
  });

  it('no budget set means no tokens (fail closed)', async () => {
    expect(await svc.lease(tenant(), 'llm', 'l1', 100)).toBe(0);
  });

  it('tenants never share a budget', async () => {
    const a = tenant();
    const b = tenant();
    await svc.setBudget(a, 'llm', 100);
    expect(await svc.lease(b, 'llm', 'l1', 100)).toBe(0);
    expect(await svc.lease(a, 'llm', 'l1', 100)).toBe(100);
  });

  it('rejects malformed input before touching Valkey', async () => {
    await expect(svc.lease('t', 'llm', 'l', 0)).rejects.toThrow();
    await expect(svc.lease('t}x', 'llm', 'l', 5)).rejects.toThrow();
    await expect(svc.setBudget('t', 'llm', -1)).rejects.toThrow();
  });

  it('Valkey unreachable: lease rejects (the caller denies), never grants', async () => {
    const down = new TokenLeaseService(config('redis://127.0.0.1:1'));
    await expect(down.lease('t', 'llm', 'l', 10)).rejects.toThrow();
    await down.onModuleDestroy();
  });
});
