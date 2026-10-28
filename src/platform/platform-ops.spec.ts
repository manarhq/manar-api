import { describe, expect, it, vi } from 'vitest';
import type { KillSwitchEpochService } from '../kill-switches/kill-switch-epoch.service';
import type { ConfigService } from '@nestjs/config';
import type { AuditService } from '../audit/audit.service';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { PlatformKillSwitchService } from '../kill-switches/platform-kill-switch.service';
import type { OpenBaoKvClient } from '../openbao/openbao-kv.client';
import type { OpenBaoPkiClient } from '../openbao/openbao-pki.client';
import type { RequestWithPlatformCaller } from './platform-auth.guard';
import { PlatformOpsController } from './platform-ops.controller';
import { AUDIT_CONCURRENCY, PlatformOpsService } from './platform-ops.service';

const req = {
  platformCaller: { clientId: 'manar-fleet', subject: 's' },
} as unknown as RequestWithPlatformCaller;
const at = new Date('2026-10-09T10:00:00.000Z');
const row = {
  active: true,
  reason: 'r',
  activatedBy: 'x',
  activatedAt: at,
  deactivatedBy: null,
  deactivatedAt: null,
};

describe('platform kill switch answers before the tenant audit chains are written', () => {
  const never = () => new Promise<never>(() => undefined);
  const ops = { auditPlatformSwitch: never } as unknown as PlatformOpsService;

  it('engage', async () => {
    const ks = {
      activate: () => Promise.resolve(row),
    } as unknown as PlatformKillSwitchService;
    const c = new PlatformOpsController(ops, ks, {} as ControlPrismaService);
    await expect(
      c.engage({ reason: 'stop now', staff: 'Mohamed' }, req),
    ).resolves.toMatchObject({ active: true });
  });

  it('release', async () => {
    const ks = {
      getState: () => Promise.resolve({ ...row, active: false }),
    } as unknown as PlatformKillSwitchService;
    const control = {
      platformKillSwitch: { updateMany: () => Promise.resolve({ count: 1 }) },
    } as unknown as ControlPrismaService;
    const c = new PlatformOpsController(ops, ks, control);
    await expect(
      c.release({ staff: 'Ali', expectedEngagementId: at.toISOString() }, req),
    ).resolves.toMatchObject({ active: false });
  });
});

describe('platform kill switch release bumps the platform epoch', () => {
  it('after the row is committed', async () => {
    const bumpPlatform = vi.fn(() => Promise.resolve());
    const ops = {
      auditPlatformSwitch: () => Promise.resolve({ audited: 0, failed: 0 }),
    } as unknown as PlatformOpsService;
    const ks = {
      getState: () => Promise.resolve({ ...row, active: false }),
    } as unknown as PlatformKillSwitchService;
    const control = {
      platformKillSwitch: { updateMany: () => Promise.resolve({ count: 1 }) },
    } as unknown as ControlPrismaService;
    const c = new PlatformOpsController(ops, ks, control, undefined, {
      bumpPlatform,
    } as unknown as KillSwitchEpochService);
    await c.release(
      { staff: 'Ali', expectedEngagementId: at.toISOString() },
      req,
    );
    expect(bumpPlatform).toHaveBeenCalledTimes(1);
  });

  it('not when the release is refused (engagement changed)', async () => {
    const bumpPlatform = vi.fn(() => Promise.resolve());
    const control = {
      platformKillSwitch: { updateMany: () => Promise.resolve({ count: 0 }) },
    } as unknown as ControlPrismaService;
    const c = new PlatformOpsController(
      {} as PlatformOpsService,
      {} as PlatformKillSwitchService,
      control,
      undefined,
      { bumpPlatform } as unknown as KillSwitchEpochService,
    );
    await expect(
      c.release({ staff: 'Ali', expectedEngagementId: at.toISOString() }, req),
    ).rejects.toThrow();
    expect(bumpPlatform).not.toHaveBeenCalled();
  });
});

describe('PlatformOpsService.auditPlatformSwitch', () => {
  it('writes tenant chains in parallel, at most AUDIT_CONCURRENCY at once, and counts failures', async () => {
    const ids = Array.from({ length: 20 }, (_, i) => `t-${i}`);
    let inFlight = 0;
    let most = 0;
    const control = {
      tenant: { findMany: () => Promise.resolve(ids.map((id) => ({ id }))) },
    } as unknown as ControlPrismaService;
    const tenants = {
      getClient: (id: string) =>
        id === 't-3'
          ? Promise.reject(new Error('tenant db down'))
          : Promise.resolve({
              $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
                inFlight++;
                most = Math.max(most, inFlight);
                await new Promise((r) => setTimeout(r, 20));
                inFlight--;
                return fn({});
              },
            }),
    } as unknown as TenantDatabaseManager;
    const audit = {
      recordInTransaction: () => Promise.resolve(() => undefined),
    } as unknown as AuditService;
    const s = new PlatformOpsService(
      {} as ConfigService<AppConfig, true>,
      control,
      tenants,
      {} as OpenBaoKvClient,
      {} as OpenBaoPkiClient,
      audit,
    );
    const r = await s.auditPlatformSwitch(
      'kill_switch.activated',
      'manar-fleet',
      {},
    );
    expect(r).toEqual({ audited: 19, failed: 1 });
    expect(most).toBeGreaterThan(1);
    expect(most).toBeLessThanOrEqual(AUDIT_CONCURRENCY);
  });

  it('writes one change after the other, so an engage lands before the release that follows', async () => {
    const ids = Array.from({ length: 10 }, (_, i) => `t-${i}`);
    const order: string[] = [];
    const control = {
      tenant: { findMany: () => Promise.resolve(ids.map((id) => ({ id }))) },
    } as unknown as ControlPrismaService;
    const tenants = {
      getClient: () =>
        Promise.resolve({
          $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
            await new Promise((r) => setTimeout(r, 10));
            return fn({});
          },
        }),
    } as unknown as TenantDatabaseManager;
    const audit = {
      recordInTransaction: (
        _tx: unknown,
        _id: string,
        e: { eventType: string },
      ) => {
        order.push(e.eventType);
        return Promise.resolve(() => undefined);
      },
    } as unknown as AuditService;
    const s = new PlatformOpsService(
      {} as ConfigService<AppConfig, true>,
      control,
      tenants,
      {} as OpenBaoKvClient,
      {} as OpenBaoPkiClient,
      audit,
    );
    await Promise.all([
      s.auditPlatformSwitch('kill_switch.activated', 'manar-fleet', {}),
      s.auditPlatformSwitch('kill_switch.deactivated', 'manar-fleet', {}),
    ]);
    expect(order).toEqual([
      ...ids.map(() => 'kill_switch.activated'),
      ...ids.map(() => 'kill_switch.deactivated'),
    ]);
  });
});
