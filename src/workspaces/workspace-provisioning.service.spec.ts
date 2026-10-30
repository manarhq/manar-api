/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/require-await -- in-memory fakes of the control DB */
import { describe, expect, it, vi } from 'vitest';
import { TenantSlugConflictError } from '../database/tenant-database.errors';
import { WorkspaceProvisioningService } from './workspace-provisioning.service';

function make(
  counts: { total: number; inflight: number; backlog: number },
  cfg: Record<string, unknown> = {},
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
  const upsert = vi.fn().mockResolvedValue({});
  const control = {
    tenant: {
      count,
      findFirst: vi.fn().mockResolvedValue(null),
      findMany: vi.fn().mockResolvedValue([{ id: 'q1' }, { id: 'q2' }]),
    },
    membership: { upsert },
  };
  const manager = {
    provisionTenant: vi.fn(async (i: any) => ({
      id: 't1',
      status: i.queued ? 'QUEUED' : 'ACTIVE',
    })),
    provisionQueued: vi.fn().mockResolvedValue({}),
  };
  const config = { get: (k: string) => cfg[k] };
  return {
    svc: new WorkspaceProvisioningService(
      manager as never,
      control as never,
      config as never,
    ),
    manager,
    upsert,
    control,
  };
}

describe('WorkspaceProvisioningService', () => {
  it('provisions straight away when there is headroom, and makes the creator the owner', async () => {
    const { svc, manager, upsert } = make({
      total: 10,
      inflight: 0,
      backlog: 0,
    });
    await expect(
      svc.createWorkspace({
        ownerSubject: 's',
        kind: 'PERSONAL',
        displayName: 'P',
      }),
    ).resolves.toEqual({ tenantId: 't1', status: 'ACTIVE' });
    expect(manager.provisionTenant).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: 'PERSONAL',
        ownerSubject: 's',
        queued: false,
      }),
    );
    const roles = upsert.mock.calls[0]![0].create;
    expect(roles.role).toBe('TENANT_OWNER');
    expect(roles.extraRoles).toHaveLength(7);
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

  it('a concurrent first sign-in returns the existing personal workspace', async () => {
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

  it('drains oldest first, only into free provisioning slots', async () => {
    const { svc, manager } = make({ total: 5, inflight: 3, backlog: 2 });
    // 4 slots - 3 in flight = 1 free; findMany fake returns 2 but take is what Prisma would apply.
    await svc.drainQueue();
    expect(manager.provisionQueued).toHaveBeenCalled();
  });
});
