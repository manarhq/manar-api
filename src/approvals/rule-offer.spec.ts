import { describe, expect, it, vi } from 'vitest';
import { ApproverDirectory } from './approver-directory';
import { HostApprovalsService } from './host-approvals.service';

type Row = {
  id: string;
  hostId: string;
  toolId: string;
  actionId: string;
  resource: string;
  highRisk: boolean;
  status: string;
  decision: string | null;
  decidedBy: string | null;
  decidedAt: Date | null;
  expiresAt: Date;
};
const DAY = 86_400_000;

function world(
  over: { history?: number; resource?: string; highRisk?: boolean } = {},
) {
  const rows: Row[] = [];
  for (let i = 0; i < (over.history ?? 3); i++)
    rows.push({
      id: `old${i}`,
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'edit',
      resource: `/home/sara/proj/src/f${i}.ts`,
      highRisk: false,
      status: 'APPROVED',
      decision: 'approve_once',
      decidedBy: 'owner',
      decidedAt: new Date(Date.now() - (i + 1) * DAY),
      expiresAt: new Date(),
    });
  const pending: Row = {
    id: 'ap1',
    hostId: 'h1',
    toolId: 'host.cursor',
    actionId: 'edit',
    resource: over.resource ?? '/home/sara/proj/src/new.ts',
    highRisk: over.highRisk ?? false,
    status: 'PENDING',
    decision: null,
    decidedBy: null,
    decidedAt: null,
    expiresAt: new Date(Date.now() + 60_000),
  };
  rows.push(pending);
  const offers: Record<string, unknown>[] = [];
  const grants: Record<string, unknown>[] = [];
  const client: Record<string, unknown> = {
    $queryRaw: () => Promise.resolve([{ now: new Date() }]),
    host: { findUnique: () => Promise.resolve({ ownerSubject: 'owner' }) },
    workspacePause: { findUnique: () => Promise.resolve(null) },
    roleBinding: { findFirst: () => Promise.resolve({ id: 'rb' }) },
    hostRuleOffer: {
      findUnique: () => Promise.resolve(offers[0] ?? null),
      upsert: ({ create }: { create: Record<string, unknown> }) => {
        offers.push(create);
        return Promise.resolve(create);
      },
    },
    approvalAllowGrant: {
      findMany: () => Promise.resolve(grants),
      create: ({ data }: { data: Record<string, unknown> }) => {
        grants.push(data);
        return Promise.resolve({ id: 'g1', ...data });
      },
    },
    hostApproval: {
      findUnique: ({ where }: { where: { id: string } }) =>
        Promise.resolve(rows.find((r) => r.id === where.id) ?? null),
      findMany: ({ where }: { where: { status: string } }) =>
        Promise.resolve(rows.filter((r) => r.status === where.status)),
      updateMany: ({
        where,
        data,
      }: {
        where: { id: string };
        data: Partial<Row>;
      }) => {
        const r = rows.find((x) => x.id === where.id && x.status === 'PENDING');
        if (!r) return Promise.resolve({ count: 0 });
        Object.assign(r, data);
        return Promise.resolve({ count: 1 });
      },
    },
  };
  client.$transaction = (fn: (tx: unknown) => unknown) =>
    Promise.resolve(fn(client));
  const control = {
    $queryRaw: () => Promise.resolve([{ t: null }]),
    tenant: {
      findUnique: () =>
        Promise.resolve({ kind: 'PERSONAL', approvalsAdminsOnly: false }),
    },
  };
  const service = new HostApprovalsService(
    { recordSafely: vi.fn().mockResolvedValue(undefined) } as never,
    { notifyApprovers: vi.fn().mockResolvedValue(0) } as never,
    new ApproverDirectory(control as never),
  );
  return { service, client: client as never, pending, offers, grants };
}

describe('rule offer after the 3rd identical approval (decision 37)', () => {
  it('offers the folder after 3 approvals, not after 2', async () => {
    const w = world();
    const m = await w.service.offersFor(w.client, [w.pending]);
    expect(m.get('ap1')).toEqual({
      scope: '/home/sara/proj/src/*',
      approvals: 3,
    });
    const few = world({ history: 2 });
    expect((await few.service.offersFor(few.client, [few.pending])).size).toBe(
      0,
    );
  });

  it('counts person approvals of the last 30 days only', async () => {
    const w = world();
    const ha = (
      w.client as {
        hostApproval: { findMany: (a: unknown) => unknown };
      }
    ).hostApproval;
    const spy = vi.spyOn(ha, 'findMany');
    await w.service.offersFor(w.client, [w.pending]);
    const where = (
      spy.mock.calls[0]![0] as {
        where: {
          decidedBy: unknown;
          decision: unknown;
          decidedAt: { gte: Date };
        };
      }
    ).where;
    expect(where.decidedBy).toEqual({ not: null });
    expect(where.decision).toEqual({ in: ['approve_once', 'approve_8h'] });
    const age = Date.now() - where.decidedAt.gte.getTime();
    expect(Math.abs(age - 30 * DAY)).toBeLessThan(5_000);
  });

  it('never for high risk, secrets, a command, or a different folder', async () => {
    for (const o of [
      { highRisk: true },
      { resource: '/home/sara/proj/src/.env' },
      { resource: '/home/sara/proj/other/x.ts' },
    ]) {
      const w = world(o);
      expect((await w.service.offersFor(w.client, [w.pending])).size).toBe(0);
    }
    const w = world();
    w.pending.actionId = 'shell';
    expect((await w.service.offersFor(w.client, [w.pending])).size).toBe(0);
  });

  it('is made once: answering the request spends it', async () => {
    const w = world();
    await w.service.decide(w.client, 't1', {
      approvalId: 'ap1',
      subject: 'owner',
      decision: 'approve_once',
      via: 'console',
      ownerMayOperate: true,
    });
    expect(w.offers).toHaveLength(1);
    expect(w.grants).toHaveLength(0);
  });

  it('accepting creates a narrow, device-scoped grant with its origin', async () => {
    const w = world();
    await w.service.decide(w.client, 't1', {
      approvalId: 'ap1',
      subject: 'owner',
      decision: 'approve_once',
      via: 'console',
      ownerMayOperate: true,
      alwaysAllowHere: true,
    });
    expect(w.grants[0]).toMatchObject({
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'edit',
      origin: 'offer',
      resourcePattern: '/home/sara/proj/src/*',
    });
  });

  it('refuses to accept where nothing was offered, or from the device', async () => {
    const none = world({ history: 1 });
    await expect(
      none.service.decide(none.client, 't1', {
        approvalId: 'ap1',
        subject: 'owner',
        decision: 'approve_once',
        via: 'console',
        ownerMayOperate: true,
        alwaysAllowHere: true,
      }),
    ).rejects.toThrow('no_rule_offer_for_this_request');
    const w = world();
    await expect(
      w.service.decide(w.client, 't1', {
        approvalId: 'ap1',
        subject: 'owner',
        decision: 'approve_once',
        via: 'device',
        alwaysAllowHere: true,
      }),
    ).rejects.toThrow('eight_hours_in_console');
    expect(w.grants).toHaveLength(0);
  });
});
