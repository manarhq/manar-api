import { describe, expect, it, vi } from 'vitest';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { AuditService } from './audit.service';
import {
  AuditFullVerifyService,
  composeVerifyResponse,
} from './audit-full-verify.service';
import { nextFullVerifyAt } from './audit-full-verify.job';

function setup(
  rows: Record<
    string,
    { verifiedAt: Date; valid: boolean; brokenAt: string | null }
  >,
) {
  const control = {
    tenant: {
      findMany: vi.fn(() =>
        Promise.resolve([{ id: 't1' }, { id: 't2' }, { id: 't3' }]),
      ),
    },
    auditFullVerification: {
      findUnique: vi.fn(({ where }: { where: { tenantId: string } }) =>
        Promise.resolve(rows[where.tenantId] ?? null),
      ),
      upsert: vi.fn(
        ({ where, create }: { where: { tenantId: string }; create: never }) => {
          rows[where.tenantId] = create;
          return Promise.resolve(create);
        },
      ),
    },
  };
  const verify = vi.fn((_c: unknown, id: string) =>
    id === 't2'
      ? Promise.resolve({ valid: false as const, brokenAt: 'evt-9' })
      : id === 't3'
        ? Promise.reject(new Error('db down'))
        : Promise.resolve({ valid: true as const }),
  );
  const svc = new AuditFullVerifyService(
    control as unknown as ControlPrismaService,
    {
      getClient: vi.fn(() => Promise.resolve({})),
    } as unknown as TenantDatabaseManager,
    { verifyAuditChain: verify } as unknown as AuditService,
  );
  return { svc, verify, rows };
}

describe('AuditFullVerifyService', () => {
  it('stores each tenant result, keeps going after an error, and runs a FULL (non-incremental) walk', async () => {
    const { svc, verify, rows } = setup({});
    expect(await svc.runAll()).toEqual({ checked: 3, failed: 1 });
    expect(verify.mock.calls.every((c) => c.length === 2)).toBe(true);
    expect(rows.t1!.valid).toBe(true);
    expect(rows.t2).toMatchObject({ valid: false, brokenAt: 'evt-9' });
    expect(rows.t3).toBeUndefined(); // errored: no result stored, stays never
  });

  it('skips tenants fully verified within the last 20 hours (second replica)', async () => {
    const now = Date.now();
    const { svc, verify } = setup({
      t1: {
        verifiedAt: new Date(now - 3_600_000),
        valid: true,
        brokenAt: null,
      },
    });
    await svc.runAll(now);
    expect(verify.mock.calls.map((c) => c[1])).toEqual(['t2', 't3']);
  });

  it('status: never / passed / failed', async () => {
    const at = new Date('2026-11-05T00:00:00Z');
    const { svc } = setup({
      ok: { verifiedAt: at, valid: true, brokenAt: null },
      bad: { verifiedAt: at, valid: false, brokenAt: 'x' },
    });
    expect((await svc.status('none')).state).toBe('never');
    expect(await svc.status('ok')).toMatchObject({
      state: 'passed',
      lastFullVerifiedAt: at,
    });
    expect(await svc.status('bad')).toMatchObject({
      state: 'failed',
      lastFullVerifiedAt: null,
    });
  });
});

describe('composeVerifyResponse', () => {
  const at = new Date('2026-11-05T22:00:00Z');
  it('passes through a good incremental plus good full check', () => {
    expect(
      composeVerifyResponse(
        { valid: true },
        { state: 'passed', lastFullVerifiedAt: at, brokenAt: null },
      ),
    ).toEqual({
      valid: true,
      lastFullVerifiedAt: at.toISOString(),
      fullCheck: 'passed',
    });
  });
  it('is never valid when the last full check failed, even if the incremental passes', () => {
    expect(
      composeVerifyResponse(
        { valid: true },
        { state: 'failed', lastFullVerifiedAt: null, brokenAt: 'evt-9' },
      ),
    ).toEqual({
      valid: false,
      brokenAt: 'evt-9',
      lastFullVerifiedAt: null,
      fullCheck: 'failed',
    });
  });
  it('a missing full check reports null, not a date', () => {
    expect(
      composeVerifyResponse(
        { valid: true },
        { state: 'never', lastFullVerifiedAt: null, brokenAt: null },
      ),
    ).toMatchObject({
      valid: true,
      lastFullVerifiedAt: null,
      fullCheck: 'never',
    });
  });
  it('incremental failure wins', () => {
    expect(
      composeVerifyResponse(
        { valid: false, brokenAt: 'c:1' },
        { state: 'passed', lastFullVerifiedAt: at, brokenAt: null },
      ),
    ).toMatchObject({ valid: false, brokenAt: 'c:1' });
  });
});

describe('nextFullVerifyAt', () => {
  it('is 22:00 UTC today or tomorrow', () => {
    expect(
      nextFullVerifyAt(new Date('2026-11-05T10:00:00Z')).toISOString(),
    ).toBe('2026-11-05T22:00:00.000Z');
    expect(
      nextFullVerifyAt(new Date('2026-11-05T22:00:00Z')).toISOString(),
    ).toBe('2026-11-06T22:00:00.000Z');
  });
});
