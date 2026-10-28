import { describe, expect, it, vi } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AuditService } from '../audit/audit.service';
import type { AppConfig } from '../config/env.validation';
import type { ControlPrismaService } from '../database/control-prisma.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { PlatformSuspension } from '../platform/platform-suspension';
import { AgentQuarantineService } from './agent-quarantine.service';
import type { KillSwitchEpochService } from './kill-switch-epoch.service';
import { PlatformKillSwitchService } from './platform-kill-switch.service';

/** Every writer of a stop condition bumps the epoch after its commit (docs/decision-path.md). */
function epochs() {
  const bumpTenant = vi.fn(() => Promise.resolve());
  const bumpPlatform = vi.fn(() => Promise.resolve());
  return {
    bumpTenant,
    bumpPlatform,
    service: { bumpTenant, bumpPlatform } as unknown as KillSwitchEpochService,
  };
}

describe('PlatformKillSwitchService.activate', () => {
  it('bumps the platform epoch', async () => {
    const e = epochs();
    const control = {
      platformKillSwitch: { upsert: () => Promise.resolve({ active: true }) },
    } as unknown as ControlPrismaService;
    await new PlatformKillSwitchService(control, undefined, e.service).activate(
      'r',
      'staff',
    );
    expect(e.bumpPlatform).toHaveBeenCalledTimes(1);
  });
});

describe('PlatformSuspension', () => {
  const audit = {
    recordInTransaction: () => Promise.resolve(() => undefined),
  } as unknown as AuditService;
  const tx = {
    userProfile: {
      upsert: () => Promise.resolve({ id: 'p' }),
      findUnique: () => Promise.resolve({ id: 'p' }),
    },
    $executeRaw: () => Promise.resolve(1),
  };
  const db = {
    $transaction: (fn: (t: typeof tx) => unknown) => Promise.resolve(fn(tx)),
  } as unknown as TenantPrismaClient;

  it('engage bumps the tenant epoch', async () => {
    const e = epochs();
    await new PlatformSuspension(audit, e.service).engage(db, 't1', 'staff');
    expect(e.bumpTenant).toHaveBeenCalledWith('t1');
  });

  it('release bumps the tenant epoch, and not when nothing was active', async () => {
    const e = epochs();
    const svc = new PlatformSuspension(audit, e.service);
    expect(await svc.release(db, 't1', 'staff')).toBe(true);
    expect(e.bumpTenant).toHaveBeenCalledWith('t1');

    const e2 = epochs();
    const none = {
      $transaction: (fn: (t: unknown) => unknown) =>
        Promise.resolve(fn({ ...tx, $executeRaw: () => Promise.resolve(0) })),
    } as unknown as TenantPrismaClient;
    expect(
      await new PlatformSuspension(audit, e2.service).release(none, 't1', 's'),
    ).toBe(false);
    expect(e2.bumpTenant).not.toHaveBeenCalled();
  });
});

describe('AgentQuarantineService', () => {
  const config = { get: () => undefined } as unknown as ConfigService<
    AppConfig,
    true
  >;
  const audit = {
    recordSafely: () => Promise.resolve(),
    record: () => Promise.resolve(),
  } as unknown as AuditService;

  it('quarantine bumps the tenant epoch', async () => {
    const e = epochs();
    const tx = {
      $queryRaw: () => Promise.resolve([]),
      agentQuarantine: {
        findUnique: () => Promise.resolve(null),
        count: () => Promise.resolve(0),
        create: () => Promise.resolve({ id: 'q', agentId: 'a' }),
      },
    };
    const db = {
      agent: { findUnique: () => Promise.resolve({ id: 'a' }) },
      $transaction: (fn: (t: typeof tx) => unknown) => Promise.resolve(fn(tx)),
    } as unknown as TenantPrismaClient;
    const out = await new AgentQuarantineService(
      audit,
      config,
      undefined,
      e.service,
    ).quarantine(db, 't1', {
      agentId: 'a',
      byAgentId: 'watcher',
      reason: 'r',
      evidence: {},
      decisionId: 'd',
      taskId: 'k',
    } as never);
    expect(out.result).toBe('quarantined');
    expect(e.bumpTenant).toHaveBeenCalledWith('t1');
  });

  it('release bumps the tenant epoch', async () => {
    const e = epochs();
    const db = {
      agentQuarantine: {
        updateMany: () => Promise.resolve({ count: 1 }),
        findUniqueOrThrow: () =>
          Promise.resolve({ id: 'q', reason: 'r', quarantinedByAgentId: 'w' }),
      },
    } as unknown as TenantPrismaClient;
    const row = await new AgentQuarantineService(
      audit,
      config,
      undefined,
      e.service,
    ).release(db, 't1', { agentId: 'a', releasedBy: 'u' });
    expect(row).not.toBeNull();
    expect(e.bumpTenant).toHaveBeenCalledWith('t1');
  });
});
