import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { AuditService } from '../audit/audit.service';
import type { KillSwitchEpochService } from './kill-switch-epoch.service';
import { KillSwitchService } from './kill-switch.service';
import type { PlatformKillSwitchService } from './platform-kill-switch.service';

/** Spec §7.2: in-memory kill switches, epoch as correctness check, bounded staleness. */
function harness(maxAgeMs = 2000) {
  const state = { tenantKilled: false, reads: 0, dbDown: false };
  const epochs = { value: '0:0', down: false };
  const tenantClient = {
    killSwitch: {
      findFirst: vi.fn(({ where }: { where: { scope: string } }) => {
        state.reads += 1;
        if (state.dbDown) return Promise.reject(new Error('db down'));
        return Promise.resolve(
          where.scope === 'TENANT' && state.tenantKilled ? { id: 'k' } : null,
        );
      }),
    },
    agentQuarantine: { findFirst: vi.fn().mockResolvedValue(null) },
    agentGroupMembership: { findMany: vi.fn().mockResolvedValue([]) },
    aiSystemAgentLink: { findMany: vi.fn().mockResolvedValue([]) },
    tool: { findUnique: vi.fn().mockResolvedValue(null) },
  } as unknown as TenantPrismaClient;
  const read = vi.fn(() =>
    epochs.down
      ? Promise.reject(new Error('valkey down'))
      : Promise.resolve(epochs.value),
  );
  const bumpTenant = vi.fn<(tenantId: string) => Promise<void>>(() => {
    epochs.value = `0:${Number(epochs.value.split(':')[1]) + 1}`;
    return Promise.resolve();
  });
  const epochService = {
    maxAgeMs,
    read,
    bumpTenant,
  } as unknown as KillSwitchEpochService;
  const service = new KillSwitchService(
    { recordSafely: vi.fn() } as unknown as AuditService,
    {
      isActive: vi.fn().mockResolvedValue(false),
    } as unknown as PlatformKillSwitchService,
    undefined,
    epochService,
  );
  const check = (tenant = 't1', agent = 'a1') =>
    service.checkAll(tenantClient, tenant, { agentId: agent });
  return { state, epochs, read, bumpTenant, service, tenantClient, check };
}

describe('KillSwitchService cache (spec 7.2)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-28T10:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('a hit with the same epoch and inside the bound makes no PostgreSQL read', async () => {
    const h = harness();
    await h.check();
    const reads = h.state.reads;
    expect(reads).toBeGreaterThan(0);
    expect(await h.check()).toEqual({ killed: false });
    expect(h.state.reads).toBe(reads);
  });

  it('a kill switch flipped with an epoch bump takes effect on the next check', async () => {
    const h = harness();
    expect((await h.check()).killed).toBe(false);
    h.state.tenantKilled = true;
    await h.bumpTenant('t1');
    expect(await h.check()).toMatchObject({
      killed: true,
      reason: 'tenant_kill_switch_active',
    });
  });

  it('a flip whose bump was lost is seen once the entry passes the max age, not before', async () => {
    const h = harness(2000);
    await h.check();
    h.state.tenantKilled = true; // no bump: writer died between commit and bump
    vi.advanceTimersByTime(2000);
    expect((await h.check()).killed).toBe(false); // exactly at the bound: still inside
    vi.advanceTimersByTime(1);
    expect((await h.check()).killed).toBe(true);
  });

  it('epoch unreadable: never serves the cache, reads PostgreSQL, caches nothing', async () => {
    const h = harness();
    await h.check('t1', 'a1'); // warm entry, not killed
    h.state.tenantKilled = true;
    h.epochs.down = true;
    expect((await h.check('t1', 'a1')).killed).toBe(true); // warm entry ignored
    expect((await h.check('t1', 'a2')).killed).toBe(true);
    h.epochs.down = false;
    h.state.tenantKilled = false;
    // a2's result from the outage was not cached, so this reads PostgreSQL again.
    expect((await h.check('t1', 'a2')).killed).toBe(false);
  });

  it('epoch unreadable and PostgreSQL down: throws so the pipeline denies', async () => {
    const h = harness();
    await h.check();
    h.epochs.down = true;
    h.state.dbDown = true;
    await expect(h.check()).rejects.toThrow('db down');
  });

  it('keys carry the tenant: another tenant never reuses an entry', async () => {
    const h = harness();
    await h.check('t1', 'a1');
    const reads = h.state.reads;
    await h.check('t2', 'a1');
    expect(h.state.reads).toBeGreaterThan(reads);
  });

  it('max age 0 turns the cache off', async () => {
    const h = harness(0);
    await h.check();
    const reads = h.state.reads;
    await h.check();
    expect(h.state.reads).toBe(reads * 2);
    expect(h.read).not.toHaveBeenCalled();
  });

  it('activate and deactivate bump the tenant epoch', async () => {
    const h = harness();
    const tc = {
      killSwitch: {
        findFirst: vi.fn().mockResolvedValue(null),
        create: vi.fn().mockResolvedValue({ id: 'k' }),
        update: vi.fn().mockResolvedValue({ id: 'k' }),
      },
    } as unknown as TenantPrismaClient;
    await h.service.activate(tc, 't1', {
      scope: 'TENANT',
      targetId: null,
      activatedBy: 'u',
    });
    expect(h.bumpTenant).toHaveBeenCalled();
    (tc.killSwitch.findFirst as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'k',
    });
    await h.service.deactivate(tc, 't1', {
      scope: 'TENANT',
      targetId: null,
      deactivatedBy: 'u',
    });
    expect(h.bumpTenant).toHaveBeenCalledTimes(2);
  });

  it('fresh bypasses the cache: a lost bump still cuts (edge refresh and reconcile)', async () => {
    const h = harness();
    await h.check(); // warm: not killed
    h.state.tenantKilled = true; // switch flipped, bump lost
    expect((await h.check()).killed).toBe(false); // the decision path may lag up to the bound
    expect(
      (
        await h.service.checkAll(
          h.tenantClient,
          't1',
          { agentId: 'a1' },
          { fresh: true },
        )
      ).killed,
    ).toBe(true);
  });

  it('checkAgent passes fresh through to checkAll', async () => {
    const h = harness();
    (h.tenantClient as unknown as { agent: unknown }).agent = {
      findUnique: vi.fn().mockResolvedValue({ status: 'ACTIVE' }),
    };
    await h.check();
    h.state.tenantKilled = true;
    expect(
      (await h.service.checkAgent(h.tenantClient, 't1', 'a1', { fresh: true }))
        .killed,
    ).toBe(true);
    expect(
      (await h.service.checkAgent(h.tenantClient, 't1', 'a1')).killed,
    ).toBe(false);
  });
});
