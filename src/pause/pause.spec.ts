import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { PauseService, highestPauseRole, mayResume } from './pause.service';
import { isWorkspacePaused } from './pause-state';

type Row = {
  paused: boolean;
  pausedBy: string | null;
  pausedByRole: string | null;
  pausedAt: Date | null;
} | null;

function fakeClient(initial = false) {
  let row: Row = initial
    ? {
        paused: true,
        pausedBy: 'u0',
        pausedByRole: 'APPROVER',
        pausedAt: new Date(),
      }
    : null;
  const hostRows = [
    {
      id: 'h1',
      hostId: 'hh',
      toolId: 'host.cursor',
      actionId: 'edit',
      status: 'PENDING',
    },
  ];
  const agentRows = [
    { id: 'a1', agentId: 'ag', toolId: 't', actionId: 'x', status: 'PENDING' },
  ];
  const flip = (rows: { id: string; status: string }[]) =>
    vi.fn(({ where }: { where: { id: string } }) => {
      const r = rows.find((x) => x.id === where.id && x.status === 'PENDING');
      if (r) r.status = 'EXPIRED';
      return Promise.resolve({ count: r ? 1 : 0 });
    });
  return {
    hostRows,
    agentRows,
    workspacePause: {
      findUnique: vi.fn(() => Promise.resolve(row)),
      upsert: vi.fn(
        ({ create, update }: { create: object; update: object }) => {
          row = (row ? { ...row, ...update } : { ...create }) as Row;
          return Promise.resolve(row);
        },
      ),
    },
    killSwitch: { findFirst: vi.fn(() => Promise.resolve(null)) },
    agentQuarantine: { findFirst: vi.fn(() => Promise.resolve(null)) },
    hostApproval: {
      findMany: vi.fn(() =>
        Promise.resolve(hostRows.filter((r) => r.status === 'PENDING')),
      ),
      updateMany: flip(hostRows),
    },
    approvalRequest: {
      findMany: vi.fn(() =>
        Promise.resolve(agentRows.filter((r) => r.status === 'PENDING')),
      ),
      updateMany: flip(agentRows),
    },
  };
}

function service(client: ReturnType<typeof fakeClient>) {
  const audit = {
    recordSafely: vi.fn<(c: unknown, t: string, e: object) => Promise<boolean>>(
      () => Promise.resolve(true),
    ),
  };
  const tenants = { getClient: vi.fn(() => Promise.resolve(client)) };
  const edge = { tenantChanged: vi.fn(() => Promise.resolve()) };
  return {
    audit,
    edge,
    svc: new PauseService(tenants as never, audit as never, edge as never),
  };
}

const OWNER = ['TENANT_OWNER'] as never;
const ADMIN = ['SECURITY_ADMIN'] as never;
const APPROVER = ['APPROVER'] as never;

describe('Pause all AI', () => {
  it('is off until pressed, then on, then off, and logs only changes', async () => {
    const c = fakeClient();
    const { svc, audit, edge } = service(c);
    expect(await svc.get('t1')).toMatchObject({
      paused: false,
      pausedBy: null,
    });
    const on = await svc.set('t1', true, 'alice', ADMIN);
    expect(on).toMatchObject({
      paused: true,
      pausedBy: 'alice',
      pausedByRole: 'SECURITY_ADMIN',
    });
    await svc.set('t1', true, 'bob', APPROVER); // second press: no second event, keeps who paused first
    expect(
      audit.recordSafely.mock.calls.filter(
        (x) =>
          (x[2] as { eventType: string }).eventType === 'workspace.ai.paused',
      ),
    ).toHaveLength(1);
    const off = await svc.set('t1', false, 'carol', OWNER);
    expect(off.paused).toBe(false);
    const types = audit.recordSafely.mock.calls.map(
      (c) => (c[2] as { eventType: string }).eventType,
    );
    expect(types).toContain('workspace.ai.paused');
    expect(types.at(-1)).toBe('workspace.ai.resumed');
    expect((await svc.get('t1')).pausedBy).toBeNull();
    // edge peers are told after every change, as for a tenant kill switch
    expect(edge.tenantChanged).toHaveBeenCalledWith('t1');
  });

  it('pausing expires everything pending with reason paused', async () => {
    const c = fakeClient();
    const { svc, audit } = service(c);
    await svc.set('t1', true, 'alice', OWNER);
    expect(c.hostRows[0]?.status).toBe('EXPIRED');
    expect(c.agentRows[0]?.status).toBe('EXPIRED');
    const expired = audit.recordSafely.mock.calls
      .map(
        (x) =>
          x[2] as {
            eventType: string;
            data: { reason?: string; expiredApprovals?: number };
          },
      )
      .filter((e) => e.eventType === 'approval.expired');
    expect(expired).toHaveLength(2);
    expect(expired.every((e) => e.data.reason === 'paused')).toBe(true);
  });

  it('only a role at least as high as the one that paused may resume', async () => {
    const c = fakeClient();
    const { svc } = service(c);
    await svc.set('t1', true, 'admin1', ADMIN);
    await expect(svc.set('t1', false, 'appr', APPROVER)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    expect((await svc.get('t1')).paused).toBe(true);
    expect((await svc.set('t1', false, 'admin2', ADMIN)).paused).toBe(false);
    await svc.set('t1', true, 'owner', OWNER);
    await expect(svc.set('t1', false, 'admin1', ADMIN)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    expect((await svc.set('t1', false, 'owner2', OWNER)).paused).toBe(false);
    await expect(
      svc.set('t1', true, 'x', ['READ_ONLY'] as never),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('role ranks', () => {
    expect(highestPauseRole(['APPROVER', 'TENANT_OWNER'] as never)).toBe(
      'TENANT_OWNER',
    );
    expect(highestPauseRole(['AUDITOR'] as never)).toBeNull();
    expect(mayResume(APPROVER, 'APPROVER')).toBe(true);
    expect(mayResume(APPROVER, null)).toBe(false);
  });

  it('every authorize path is denied with reason paused (kill-switch check)', async () => {
    const c = fakeClient(true);
    const ks = new KillSwitchService(
      { recordSafely: vi.fn() } as never,
      { isActive: () => Promise.resolve(false) } as never,
    );
    const r = await ks.checkAll(c as never, 't1', {
      agentId: 'a',
      toolId: 'host.cursor',
    });
    expect(r).toEqual({ killed: true, scope: 'PAUSE', reason: 'paused' });
  });

  it('fails closed when the pause row cannot be read', async () => {
    const c = fakeClient();
    c.workspacePause.findUnique.mockRejectedValueOnce(new Error('db down'));
    await expect(isWorkspacePaused(c as never)).rejects.toThrow('db down');
  });
});
