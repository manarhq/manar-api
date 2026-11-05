/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/require-await -- in-memory fakes of the control DB */
import { describe, expect, it, vi } from 'vitest';
import {
  TenantCreatorLimitError,
  TenantProvisioningError,
  TenantSlugConflictError,
} from '../database/tenant-database.errors';
import {
  MAX_PROVISION_ATTEMPTS,
  TenantDatabaseManager,
  provisionBackoffMs,
} from '../database/tenant-database-manager.service';
import {
  SampleDirectoryService,
  WorkspaceProvisioningService,
} from './workspace-provisioning.service';

const ISSUER = 'https://auth.test/realms/manar';

function make(
  counts: { total: number; inflight: number; backlog: number },
  cfg: Record<string, unknown> = {},
  throttle = {
    increment: vi.fn().mockResolvedValue({
      totalHits: 1,
      timeToExpire: 30,
      isBlocked: false,
      timeToBlockExpire: 0,
    }),
  },
) {
  const count = vi.fn(({ where }: any) =>
    Promise.resolve(
      where.status === 'PROVISIONING'
        ? counts.inflight
        : where.status === 'QUEUED'
          ? counts.backlog
          : counts.total,
    ),
  );
  const control = {
    tenant: {
      count,
      findFirst: vi.fn().mockResolvedValue(null),
      findUnique: vi.fn().mockResolvedValue(null),
      findMany: vi.fn().mockResolvedValue([{ id: 'q1' }, { id: 'q2' }]),
      updateMany: vi.fn().mockResolvedValue({ count: 1 }),
    },
  };
  const manager = {
    provisionTenant: vi.fn(async (i: any) => ({
      id: 't1',
      status: i.queued ? 'QUEUED' : 'ACTIVE',
    })),
    provisionQueued: vi.fn().mockResolvedValue({}),
    scheduleProvisionRetry: vi.fn().mockResolvedValue(undefined),
  };
  const config = { get: (k: string) => ({ AUTH_ISSUERS: ISSUER, ...cfg })[k] };
  return {
    svc: new WorkspaceProvisioningService(
      manager as never,
      control as never,
      config as never,
      throttle as never,
    ),
    manager,
    control,
    config,
  };
}

const OK = {
  totalHits: 1,
  timeToExpire: 30,
  isBlocked: false,
  timeToBlockExpire: 0,
};
const OVER = {
  totalHits: 999,
  timeToExpire: 30,
  isBlocked: true,
  timeToBlockExpire: 30,
};

/** A throttle that refuses only the named buckets, recording every spend in order. */
function throttleRefusing(...buckets: string[]) {
  const spent: string[] = [];
  return {
    spent,
    increment: vi.fn(
      async (
        key: string,
        _ttl: number,
        _limit: number,
        _b: number,
        bucket: string,
      ) => {
        spent.push(`${bucket}:${key.split(':')[0]}`);
        return buckets.includes(bucket) ? OVER : OK;
      },
    ),
  };
}

describe('WorkspaceProvisioningService creation rate', () => {
  const counts = { total: 1, inflight: 0, backlog: 0 };
  const personal = {
    ownerSubject: 's',
    kind: 'PERSONAL' as const,
    displayName: 'P',
  };

  it('refuses over the hourly deployment-wide rate with a friendly 429, creating nothing', async () => {
    const throttle = throttleRefusing('workspace-create');
    const { svc, manager } = make(counts, {}, throttle);
    const refused = await svc
      .createWorkspace(personal)
      .catch((e: unknown) => e);
    expect(refused).toMatchObject({
      status: 429,
      response: {
        reason: 'workspace_creation_busy',
        retryAfterSeconds: 60,
        message: {
          en: expect.stringContaining('try again'),
          ar: expect.any(String),
        },
      },
    });
    expect(manager.provisionTenant).not.toHaveBeenCalled();
    expect(throttle.increment).toHaveBeenLastCalledWith(
      'global',
      3_600_000,
      120,
      0,
      'workspace-create',
    );
  });

  it("spends the person's own bucket first, so one account cannot drain the global budget", async () => {
    const throttle = throttleRefusing('workspace-create-person');
    const { svc, manager } = make(counts, {}, throttle);
    await expect(svc.createWorkspace(personal)).rejects.toMatchObject({
      status: 429,
      response: { reason: 'workspace_creation_rate_limited' },
    });
    expect(throttle.spent).toEqual(['workspace-create-person:PERSONAL']);
    expect(manager.provisionTenant).not.toHaveBeenCalled();
  });

  it('bounds re-creating the sample workspace per person, per day', async () => {
    const throttle = throttleRefusing();
    const { svc } = make(counts, {}, throttle);
    await svc.createWorkspace({
      ownerSubject: 's',
      kind: 'SAMPLE',
      displayName: 'S',
    });
    expect(throttle.increment.mock.calls[0]!.slice(1, 3)).toEqual([
      86_400_000, 3,
    ]);
  });

  it('spends the Entra tenant bucket for a company trial', async () => {
    const throttle = throttleRefusing('workspace-create-entra');
    const { svc } = make(counts, {}, throttle);
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'COMPANY',
        displayName: 'C',
        entraTenantId: 'TID-1',
      }),
    ).rejects.toMatchObject({ status: 429 });
    expect(throttle.spent).toEqual([
      'workspace-create-person:COMPANY',
      'workspace-create-entra:tid-1',
    ]);
  });

  it('uses the configured global rate', async () => {
    const throttle = throttleRefusing();
    const { svc } = make(counts, { WORKSPACE_CREATE_PER_HOUR: 5 }, throttle);
    await svc.createWorkspace(personal);
    expect(throttle.increment).toHaveBeenLastCalledWith(
      'global',
      3_600_000,
      5,
      0,
      'workspace-create',
    );
  });

  it('fails closed (503) when the limits store is down', async () => {
    const { svc, manager } = make(
      counts,
      {},
      {
        increment: vi.fn().mockRejectedValue(new Error('redis down')),
      },
    );
    await expect(svc.createWorkspace(personal)).rejects.toMatchObject({
      status: 503,
    });
    expect(manager.provisionTenant).not.toHaveBeenCalled();
  });

  it('passes the creator and the per-creator cap into the tenant transaction, and maps its refusal', async () => {
    const { svc, manager } = make(counts, {}, throttleRefusing());
    manager.provisionTenant.mockRejectedValueOnce(
      new TenantCreatorLimitError(3),
    );
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'COMPANY',
        displayName: 'C',
        entraTenantId: 'tid',
        maxPerCreator: 3,
      }),
    ).rejects.toMatchObject({
      status: 403,
      response: { reason: 'company_trial_limit_reached' },
    });
    expect(manager.provisionTenant.mock.calls[0]![0].creator).toEqual({
      issuer: ISSUER,
      subject: 's',
      maxOfKind: 3,
    });
  });
});

describe('WorkspaceProvisioningService', () => {
  it('provisions straight away and hands the owner to the same transaction as the tenant rows', async () => {
    const { svc, manager } = make({ total: 10, inflight: 0, backlog: 0 });
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'PERSONAL',
        displayName: 'P',
      }),
    ).resolves.toEqual({ tenantId: 't1', status: 'ACTIVE' });
    const input = manager.provisionTenant.mock.calls[0]![0];
    expect(input).toMatchObject({
      kind: 'PERSONAL',
      ownerSubject: 's',
      ownerIssuer: ISSUER,
      queued: false,
      retryOnFailure: true,
    });
    expect(input.owner).toMatchObject({
      issuer: ISSUER,
      subject: 's',
      role: 'TENANT_OWNER',
    });
    expect(input.owner.extraRoles).toHaveLength(7);
  });

  it('an explicit owner issuer wins over the default', async () => {
    const { svc, manager } = make({ total: 1, inflight: 0, backlog: 0 });
    await svc.createWorkspace({
      ownerIssuer: 'https://other/realms/x/',
      ownerSubject: 's',
      kind: 'PERSONAL',
      displayName: 'P',
    });
    expect(manager.provisionTenant.mock.calls[0]![0].owner.issuer).toBe(
      'https://other/realms/x',
    );
  });

  it.each([
    ['provisioning is saturated', { total: 10, inflight: 4, backlog: 0 }, {}],
    ['a backlog exists (FIFO)', { total: 10, inflight: 0, backlog: 3 }, {}],
    [
      'the database count is near its limit',
      { total: 96, inflight: 0, backlog: 0 },
      { WORKSPACE_MAX_TENANTS: 100 },
    ],
  ])('queues instead of refusing when %s', async (_n, counts, cfg) => {
    const { svc, manager } = make(counts, cfg);
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'PERSONAL',
        displayName: 'P',
      }),
    ).resolves.toEqual({ tenantId: 't1', status: 'QUEUED' });
    expect(manager.provisionTenant).toHaveBeenCalledWith(
      expect.objectContaining({ queued: true }),
    );
  });

  it('in-flight only counts attempts touched recently, so failed ones cannot stall sign-ups', async () => {
    const { svc, control } = make({ total: 1, inflight: 0, backlog: 0 });
    await svc.shouldQueue();
    const call = control.tenant.count.mock.calls
      .map((c: any) => c[0].where)
      .find((w: any) => w.status === 'PROVISIONING');
    expect(call.updatedAt.gt).toBeInstanceOf(Date);
    expect(Date.now() - call.updatedAt.gt.getTime()).toBeGreaterThan(
      5 * 60_000,
    );
  });

  it('a failed database leg is not an error for the user: the tenant is queued for retry', async () => {
    const { svc, manager, control } = make({
      total: 1,
      inflight: 0,
      backlog: 0,
    });
    manager.provisionTenant.mockRejectedValueOnce(
      new TenantProvisioningError('x', new Error('db')),
    );
    control.tenant.findUnique.mockResolvedValueOnce({ id: 't9' });
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'PERSONAL',
        displayName: 'P',
      }),
    ).resolves.toEqual({ tenantId: 't9', status: 'QUEUED' });
  });

  it('a concurrent first sign-in returns the existing personal workspace of the same issuer', async () => {
    const { svc, manager, control } = make({
      total: 1,
      inflight: 0,
      backlog: 0,
    });
    manager.provisionTenant.mockRejectedValueOnce(
      new TenantSlugConflictError('x'),
    );
    control.tenant.findFirst.mockResolvedValueOnce({
      id: 'existing',
      status: 'ACTIVE',
    });
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'PERSONAL',
        displayName: 'P',
      }),
    ).resolves.toEqual({ tenantId: 'existing', status: 'ACTIVE' });
    expect(control.tenant.findFirst.mock.calls[0]![0].where).toMatchObject({
      ownerIssuer: ISSUER,
      ownerSubject: 's',
    });
  });

  it('a second company workspace for one Entra tenant is a conflict', async () => {
    const { svc, manager } = make({ total: 1, inflight: 0, backlog: 0 });
    manager.provisionTenant.mockRejectedValueOnce(
      new TenantSlugConflictError('x'),
    );
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'COMPANY',
        displayName: 'C',
        entraTenantId: 't',
      }),
    ).rejects.toThrow('workspace_exists');
  });

  it('refuses to create a workspace when no issuer is known', async () => {
    const { svc } = make(
      { total: 1, inflight: 0, backlog: 0 },
      { AUTH_ISSUERS: '' },
    );
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'PERSONAL',
        displayName: 'P',
      }),
    ).rejects.toThrow('issuer_required');
  });

  it('drain re-queues stalled attempts, then takes due queued tenants oldest first', async () => {
    const { svc, manager, control } = make({
      total: 5,
      inflight: 0,
      backlog: 2,
    });
    control.tenant.findMany
      .mockResolvedValueOnce([{ id: 'stalled' }])
      .mockResolvedValueOnce([{ id: 'q1' }, { id: 'q2' }]);
    await svc.drainQueue();
    expect(manager.scheduleProvisionRetry).toHaveBeenCalledWith('stalled');
    const due = control.tenant.findMany.mock.calls[1]![0];
    const stalledWhere = control.tenant.findMany.mock.calls[0]![0].where;
    expect(stalledWhere.OR).toEqual([
      { ownerIssuer: { not: null } },
      { entraTenantId: { not: null } },
    ]);
    expect(stalledWhere.kind).toBeUndefined();
    expect(due.where.OR).toEqual([
      { nextProvisionAt: null },
      { nextProvisionAt: { lte: expect.any(Date) } },
    ]);
    expect(due.orderBy).toEqual({ createdAt: 'asc' });
    expect(manager.provisionQueued).toHaveBeenCalledTimes(2);
  });

  it('retryFailed puts FAILED workspaces back in the queue with a fresh count', async () => {
    const { svc, control } = make({ total: 1, inflight: 0, backlog: 0 });
    await expect(svc.retryFailed('t1')).resolves.toBe(1);
    expect(control.tenant.updateMany).toHaveBeenCalledWith({
      where: { status: 'FAILED', id: 't1' },
      data: { status: 'QUEUED', provisionAttempts: 0, nextProvisionAt: null },
    });
  });
});

describe('provisioning retry policy (TenantDatabaseManager.scheduleProvisionRetry)', () => {
  function manager(row: { status: string; provisionAttempts: number } | null) {
    const updateMany = vi.fn().mockResolvedValue({ count: 1 });
    const control = {
      tenant: { findUnique: vi.fn().mockResolvedValue(row), updateMany },
    };
    const m = new TenantDatabaseManager(
      control as never,
      { get: () => 1000 } as never,
      {} as never,
    );
    return { m, updateMany };
  }

  it('re-queues with an exponential back-off', async () => {
    const { m, updateMany } = manager({
      status: 'PROVISIONING',
      provisionAttempts: 1,
    });
    const before = Date.now();
    await m.scheduleProvisionRetry('t');
    const data = updateMany.mock.calls[0]![0].data;
    expect(data).toMatchObject({ status: 'QUEUED', provisionAttempts: 2 });
    expect(data.nextProvisionAt.getTime() - before).toBeGreaterThanOrEqual(
      provisionBackoffMs(2) - 50,
    );
    expect(provisionBackoffMs(1)).toBe(30_000);
    expect(provisionBackoffMs(20)).toBe(30 * 60_000);
    await m.onModuleDestroy();
  });

  it(`gives up as FAILED after ${MAX_PROVISION_ATTEMPTS} attempts`, async () => {
    const { m, updateMany } = manager({
      status: 'PROVISIONING',
      provisionAttempts: MAX_PROVISION_ATTEMPTS - 1,
    });
    await m.scheduleProvisionRetry('t');
    expect(updateMany.mock.calls[0]![0].data).toMatchObject({
      status: 'FAILED',
    });
    await m.onModuleDestroy();
  });

  it('does nothing to a tenant that is not PROVISIONING', async () => {
    const { m, updateMany } = manager({
      status: 'ACTIVE',
      provisionAttempts: 0,
    });
    await m.scheduleProvisionRetry('t');
    expect(updateMany).not.toHaveBeenCalled();
    await m.onModuleDestroy();
  });
});

describe('SAMPLE workspaces', () => {
  it('creates a sample owned by that one subject, in the same transaction as its rows', async () => {
    const { svc, manager } = make({ total: 1, inflight: 0, backlog: 0 });
    await svc.createWorkspace({
      ownerSubject: 'me',
      kind: 'SAMPLE',
      displayName: 'Sample',
    });
    const input = manager.provisionTenant.mock.calls[0]![0];
    expect(input).toMatchObject({ kind: 'SAMPLE', ownerSubject: 'me' });
    expect(input.owner.subject).toBe('me');
  });

  it('refuses to delete anything that is not a SAMPLE', async () => {
    const { svc, control } = make({ total: 1, inflight: 0, backlog: 0 });
    control.tenant.findUnique.mockResolvedValue({
      id: 'p',
      kind: 'PERSONAL',
      status: 'ACTIVE',
      databaseBinding: {},
    });
    await expect(svc.deleteWorkspace('p')).rejects.toThrow(
      'only_sample_workspaces_can_be_deleted',
    );
  });

  it('deletes a sample: deprovision, drop the database, remove the rows', async () => {
    const { svc, manager, control } = make({
      total: 1,
      inflight: 0,
      backlog: 0,
    });
    const tx = vi.fn().mockResolvedValue([]);
    (control as any).$transaction = tx;
    for (const k of [
      'auditSealMark',
      'auditFullVerification',
      'secretReference',
      'reportShare',
      'weeklyReportCard',
      'installCode',
      'publicProfile',
      'workspaceInvite',
      'tenantDatabaseBinding',
    ])
      (control as any)[k] = { deleteMany: vi.fn() };
    (control.tenant as any).delete = vi.fn();
    control.tenant.findUnique.mockResolvedValue({
      id: 's',
      kind: 'SAMPLE',
      status: 'ACTIVE',
      updatedAt: new Date(),
      databaseBinding: {},
    });
    Object.assign(manager, {
      deprovisionTenant: vi.fn(),
      dangerouslyDropTenantDatabase: vi.fn(),
    });
    await svc.deleteWorkspace('s');
    expect((manager as any).deprovisionTenant).toHaveBeenCalledWith('s');
    expect((manager as any).dangerouslyDropTenantDatabase).toHaveBeenCalledWith(
      's',
    );
    expect(tx).toHaveBeenCalled();
  });

  it('the directory only matches the owner by issuer, subject and an ACTIVE membership', async () => {
    const { control, config } = make({ total: 1, inflight: 0, backlog: 0 });
    const dir = new SampleDirectoryService(control as never, config as never);
    control.tenant.findFirst.mockResolvedValueOnce({ id: 'sample-1' });
    await expect(dir.find('me')).resolves.toBe('sample-1');
    expect(control.tenant.findFirst.mock.calls[0]![0].where).toMatchObject({
      kind: 'SAMPLE',
      ownerIssuer: ISSUER,
      ownerSubject: 'me',
      memberships: {
        some: { issuer: ISSUER, subject: 'me', status: 'ACTIVE' },
      },
    });
    control.tenant.findFirst.mockResolvedValueOnce({ id: 'sample-1' });
    await expect(dir.find('me', 'https://other/realms/x')).resolves.toBe(
      'sample-1',
    );
    expect(control.tenant.findFirst.mock.calls[1]![0].where.ownerIssuer).toBe(
      'https://other/realms/x',
    );
  });
});
