import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { HostApprovalsController } from './host-approvals.controller';
import { HostApprovalsService } from './host-approvals.service';
import type { HostContext } from '../host-mtls/host-context';

type Row = {
  id: string;
  hostId: string;
  toolId: string;
  actionId: string;
  resource: string;
  summary: string;
  highRisk: boolean;
  status: string;
  decision: string | null;
  expiresAt: Date;
  createdAt: Date;
};

function world(opts: { approverSubjects: string[]; highRisk?: boolean }) {
  const rows: Row[] = [
    {
      id: 'ap1',
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'file.read',
      resource: '/u/.aws/credentials',
      summary: 'Cursor wants to read a file',
      highRisk: opts.highRisk ?? false,
      status: 'PENDING',
      decision: null,
      expiresAt: new Date(Date.now() + 60_000),
      createdAt: new Date(),
    },
  ];
  const grants: Record<string, unknown>[] = [];
  const client: Record<string, unknown> = {
    roleBinding: {
      findFirst: ({
        where,
      }: {
        where: { user: { keycloakSubject: string } };
      }) =>
        Promise.resolve(
          opts.approverSubjects.includes(where.user.keycloakSubject)
            ? { id: 'rb' }
            : null,
        ),
    },
    hostApproval: {
      create: ({ data }: { data: Partial<Row> }) => {
        const r = {
          id: 'ap2',
          status: 'PENDING',
          decision: null,
          createdAt: new Date(),
          ...data,
        } as Row;
        rows.push(r);
        return Promise.resolve(r);
      },
      findUnique: ({ where }: { where: { id: string } }) =>
        Promise.resolve(rows.find((r) => r.id === where.id) ?? null),
      findMany: ({ where }: { where: { hostId?: string } }) =>
        Promise.resolve(
          rows.filter(
            (r) =>
              r.status === 'PENDING' &&
              (!where.hostId || r.hostId === where.hostId),
          ),
        ),
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
    approvalAllowGrant: {
      create: ({ data }: { data: Record<string, unknown> }) => {
        grants.push(data);
        return Promise.resolve({ id: 'g1', ...data });
      },
    },
  };
  client.$transaction = (fn: (tx: unknown) => unknown) =>
    Promise.resolve(fn(client));
  const audit = { recordSafely: vi.fn().mockResolvedValue(undefined) };
  const push = { notifyApprovers: vi.fn().mockResolvedValue(0) };
  const service = new HostApprovalsService(audit as never, push as never);
  const controller = new HostApprovalsController(service, {
    getClient: () => Promise.resolve(client),
  } as never);
  return { controller, service, rows, grants, audit, push, client };
}

const host = (over: Partial<HostContext> = {}): HostContext => ({
  hostId: 'h1',
  tenantId: 't1',
  machineId: 'm1',
  ownerSubject: 'owner',
  status: 'APPROVED',
  ...over,
});

describe('device decisions (spec 4.6)', () => {
  it('lets the owner approve once and records who and where', async () => {
    const w = world({ approverSubjects: ['owner'] });
    const r = await w.controller.decide(host(), 'ap1', {
      decision: 'approve_once',
    });
    expect(r).toMatchObject({ status: 'APPROVED', decision: 'approve_once' });
    expect(w.grants).toHaveLength(0);
    expect(w.rows[0]).toMatchObject({
      decidedBy: 'owner',
      decidedVia: 'device',
    });
  });

  it('approve_8h creates a grant scoped to this host, tool, action and resource', async () => {
    const w = world({ approverSubjects: ['owner'] });
    await w.controller.decide(host(), 'ap1', { decision: 'approve_8h' });
    expect(w.grants[0]).toMatchObject({
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'file.read',
      resource: '/u/.aws/credentials',
      createdBy: 'owner',
    });
    expect(w.audit.recordSafely).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({ eventType: 'approval.grant.created' }),
    );
  });

  it('refuses when the host owner may not approve in this workspace', async () => {
    const w = world({ approverSubjects: ['someone-else'] });
    await expect(
      w.controller.decide(host(), 'ap1', { decision: 'approve_once' }),
    ).rejects.toThrow('owner_is_not_an_approver');
    expect(w.rows[0]!.status).toBe('PENDING');
  });

  it('refuses a host with no owner or one still waiting for approval', async () => {
    const w = world({ approverSubjects: ['owner'] });
    await expect(
      w.controller.decide(host({ ownerSubject: null }), 'ap1', {
        decision: 'approve_once',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(
      w.controller.decide(host({ status: 'PENDING' }), 'ap1', {
        decision: 'approve_once',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('refuses high-risk actions from the device ("open in console")', async () => {
    const w = world({ approverSubjects: ['owner'], highRisk: true });
    await expect(
      w.controller.decide(host(), 'ap1', { decision: 'approve_once' }),
    ).rejects.toThrow('high_risk_open_in_console');
    const pending = await w.controller.pending(host());
    expect(pending.items[0]).toMatchObject({
      highRisk: true,
      decidableHere: false,
    });
    // the console can still decide it
    const r = await w.service.decide(w.client as never, 't1', {
      approvalId: 'ap1',
      subject: 'owner',
      decision: 'approve_once',
      via: 'console',
    });
    expect(r.status).toBe('APPROVED');
  });

  it("cannot decide another device's approval", async () => {
    const w = world({ approverSubjects: ['owner'] });
    await expect(
      w.controller.decide(host({ hostId: 'h2' }), 'ap1', {
        decision: 'approve_once',
      }),
    ).rejects.toThrow('no such approval');
    expect(
      (await w.controller.pending(host({ hostId: 'h2' }))).items,
    ).toHaveLength(0);
  });

  it('decides once: a second decision conflicts', async () => {
    const w = world({ approverSubjects: ['owner'] });
    await w.controller.decide(host(), 'ap1', { decision: 'deny' });
    await expect(
      w.controller.decide(host(), 'ap1', { decision: 'approve_once' }),
    ).rejects.toThrow('already decided');
  });

  it('rejects unknown decision values', async () => {
    const w = world({ approverSubjects: ['owner'] });
    await expect(
      w.controller.decide(host(), 'ap1', { decision: 'approve_forever' }),
    ).rejects.toThrow();
  });

  it('console make-rule returns an exact-resource ALLOW draft', async () => {
    const w = world({ approverSubjects: ['owner'] });
    const r = await w.service.decide(w.client as never, 't1', {
      approvalId: 'ap1',
      subject: 'owner',
      decision: 'approve_once',
      via: 'console',
      makeRule: true,
    });
    expect(r.ruleDraft).toMatchObject({
      effect: 'ALLOW',
      toolId: 'host.cursor',
      actionId: 'file.read',
      resourcePattern: '/u/.aws/credentials',
    });
  });

  it('opening an approval pushes to approvers', async () => {
    const w = world({ approverSubjects: ['owner'] });
    await w.service.open(w.client as never, 't1', {
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'file.read',
      resource: 'r',
      summary: 's',
      highRisk: false,
      toolName: 'Cursor',
    });
    expect(w.push.notifyApprovers).toHaveBeenCalledWith(
      w.client,
      't1',
      expect.objectContaining({ kind: 'approval', url: '/approvals' }),
    );
  });
});
