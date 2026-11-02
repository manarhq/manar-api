import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { HostApprovalsController } from './host-approvals.controller';
import { HostApprovalsService } from './host-approvals.service';
import { buildRuleDraft } from './rule-draft';
import { ApproverDirectory } from './approver-directory';
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

function world(opts: {
  approverSubjects: string[];
  paused?: boolean;
  highRisk?: boolean;
  recent?: number;
  /** The workspace's "admins only" switch (a COMPANY workspace). */
  adminsOnly?: boolean;
}) {
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
  const nonces = new Set<string>();
  const client: Record<string, unknown> = {
    $queryRaw: () => Promise.resolve([{ now: new Date() }]),
    host: {
      findUnique: ({ where }: { where: { id: string } }) =>
        Promise.resolve(
          where.id === 'h1'
            ? { ownerSubject: 'owner' }
            : { ownerSubject: 'other-owner' },
        ),
    },
    workspacePause: {
      findUnique: () => Promise.resolve(opts.paused ? { paused: true } : null),
    },
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
      findFirst: ({ where }: { where: Partial<Row> }) =>
        Promise.resolve(
          rows.find(
            (r) =>
              r.status === 'PENDING' &&
              r.hostId === where.hostId &&
              r.toolId === where.toolId &&
              r.actionId === where.actionId &&
              r.resource === where.resource,
          ) ?? null,
        ),
      count: () => Promise.resolve(opts.recent ?? 0),
      findMany: ({
        where,
      }: {
        where: { hostId?: string; expiresAt?: { gt?: Date; lte?: Date } };
      }) =>
        Promise.resolve(
          rows.filter(
            (r) =>
              r.status === 'PENDING' &&
              (!where.hostId || r.hostId === where.hostId) &&
              (!where.expiresAt?.gt || r.expiresAt > where.expiresAt.gt) &&
              (!where.expiresAt?.lte || r.expiresAt <= where.expiresAt.lte),
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
    phoneActionUse: {
      create: ({ data }: { data: { nonce: string } }) => {
        if (nonces.has(data.nonce)) return Promise.reject(new Error('unique'));
        nonces.add(data.nonce);
        return Promise.resolve({});
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
  // The real rule, over a control database without the memberships table (role bindings decide)
  // and with this workspace's "admins only" switch.
  const control = {
    $queryRaw: () => Promise.resolve([{ t: null }]),
    tenant: {
      findUnique: () =>
        Promise.resolve({
          kind: 'COMPANY',
          approvalsAdminsOnly: opts.adminsOnly ?? false,
        }),
    },
  };
  const approvers = new ApproverDirectory(control as never);
  const service = new HostApprovalsService(
    audit as never,
    push as never,
    approvers,
  );
  const controller = new HostApprovalsController(
    service,
    { getClient: () => Promise.resolve(client) } as never,
    approvers,
  );
  return { controller, service, rows, grants, audit, push, client, nonces };
}

const host = (over: Partial<HostContext> = {}): HostContext => ({
  hostId: 'h1',
  tenantId: 't1',
  machineId: 'm1',
  ownerSubject: 'owner',
  status: 'APPROVED',
  ...over,
});

const make8h = () => world({ approverSubjects: ['owner'] });

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

  it('refuses approve_8h from the device: 8 hours is a console decision', async () => {
    const w = make8h();
    await expect(
      w.controller.decide(host(), 'ap1', { decision: 'approve_8h' }),
    ).rejects.toThrow('eight_hours_in_console');
    expect(w.grants).toHaveLength(0);
    expect(w.rows[0]!.status).toBe('PENDING');
  });

  it('a push decision spends its token in the decision, once, and refuses 8 hours', async () => {
    const w = world({ approverSubjects: ['owner'] });
    const nonce = { value: 'n1', expiresAt: new Date(Date.now() + 60_000) };
    await w.service.decide(w.client as never, 't1', {
      approvalId: 'ap1',
      subject: 'owner',
      decision: 'approve_once',
      via: 'push',
      nonce,
    });
    expect(w.nonces.has('n1')).toBe(true);
    expect(w.rows[0]).toMatchObject({ decidedVia: 'push' });
    const again = world({ approverSubjects: ['owner'] });
    again.nonces.add('n1');
    await expect(
      again.service.decide(again.client as never, 't1', {
        approvalId: 'ap1',
        subject: 'owner',
        decision: 'deny',
        via: 'push',
        nonce,
      }),
    ).rejects.toMatchObject({ response: { reason: 'action_already_used' } });
    await expect(
      w.service.decide(w.client as never, 't1', {
        approvalId: 'ap1',
        subject: 'owner',
        decision: 'approve_8h',
        via: 'push',
      }),
    ).rejects.toThrow();
  });

  it('opens with a match code in the stored summary, one tag per approval, and no resource in the push', async () => {
    const w = world({ approverSubjects: ['owner'] });
    const row = await w.service.open(w.client as never, 't1', {
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'file.write',
      resource: '/u/.ssh/id_rsa',
      summary: 'Cursor: file.write',
      highRisk: false,
      toolName: 'Cursor',
    });
    expect(row.summary).toMatch(/ #[0-9A-F]{4}$/);
    const payload = w.push.notifyApprovers.mock.calls.at(-1)![2] as {
      tag: string;
      body: string;
    };
    expect(payload.tag).toBe(`approval-${row.id}`);
    expect(payload.body).toMatch(/^Cursor: file\.write #[0-9A-F]{4}$/);
    expect(payload.body).not.toContain('id_rsa');
  });

  it('approve_8h from the console creates a grant scoped to this host, tool, action and resource', async () => {
    const w = world({ approverSubjects: ['owner'] });
    await w.service.decide(w.client as never, 't1', {
      approvalId: 'ap1',
      subject: 'owner',
      decision: 'approve_8h',
      via: 'console',
    });
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

  it('the device owner decides their own device without an approver role', async () => {
    const w = world({ approverSubjects: ['someone-else'] });
    const r = await w.controller.decide(host(), 'ap1', {
      decision: 'approve_once',
    });
    expect(r).toMatchObject({ status: 'APPROVED' });
    expect((await w.controller.pending(host())).ownerMayApprove).toBe(true);
  });

  it('"admins only" stops the owner, and says so on the device', async () => {
    const w = world({ approverSubjects: ['someone-else'], adminsOnly: true });
    await expect(
      w.controller.decide(host(), 'ap1', { decision: 'approve_once' }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(w.rows[0]!.status).toBe('PENDING');
    expect((await w.controller.pending(host())).ownerMayApprove).toBe(false);
  });

  it("a member cannot decide someone else's device, through any channel", async () => {
    const w = world({ approverSubjects: ['admin'] });
    for (const via of ['console', 'push', 'telegram'] as const) {
      await expect(
        w.service.decide(w.client as never, 't1', {
          approvalId: 'ap1',
          subject: 'a-member',
          decision: 'approve_once',
          via,
        }),
      ).rejects.toBeInstanceOf(ForbiddenException);
    }
    expect(w.rows[0]!.status).toBe('PENDING');
  });

  it('an owner who is not an approver cannot give 8 hours, even in the console', async () => {
    const w = world({ approverSubjects: [] });
    await expect(
      w.service.decide(w.client as never, 't1', {
        approvalId: 'ap1',
        subject: 'owner',
        decision: 'approve_8h',
        via: 'console',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    expect(w.grants).toHaveLength(0);
  });

  it('an approver decides any device', async () => {
    const w = world({ approverSubjects: ['admin'], adminsOnly: true });
    const r = await w.service.decide(w.client as never, 't1', {
      approvalId: 'ap1',
      subject: 'admin',
      decision: 'approve_8h',
      via: 'console',
    });
    expect(r.status).toBe('APPROVED');
  });

  it('the device giving up is recorded as withdrawn, not as a deny by a person', async () => {
    const w = world({ approverSubjects: [], adminsOnly: true });
    const r = await w.controller.decide(host(), 'ap1', {
      decision: 'deny',
      withdraw: true,
    });
    expect(r.status).toBe('EXPIRED');
    expect(w.rows[0]).toMatchObject({
      status: 'EXPIRED',
      endReason: 'withdrawn',
    });
    expect(w.rows[0]).not.toHaveProperty('decidedBy');
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
    ).rejects.toMatchObject({ response: { reason: 'already_decided' } });
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

  it('reuses a pending approval for the same host, tool, action and resource', async () => {
    const w = world({ approverSubjects: ['owner'] });
    const again = await w.service.open(w.client as never, 't1', {
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'file.read',
      resource: '/u/.aws/credentials',
      summary: 's',
      highRisk: false,
      toolName: 'Cursor',
    });
    expect(again.id).toBe('ap1');
    expect(w.rows).toHaveLength(1);
    expect(w.push.notifyApprovers).not.toHaveBeenCalled();
  });

  it('refuses to open more approvals than the per-device limit', async () => {
    const w = world({ approverSubjects: ['owner'], recent: 20 });
    await expect(
      w.service.open(w.client as never, 't1', {
        hostId: 'h1',
        toolId: 'host.cursor',
        actionId: 'shell',
        resource: 'x',
        summary: 's',
        highRisk: false,
        toolName: 'Cursor',
      }),
    ).rejects.toMatchObject({ status: 429 });
  });

  it('pushes with one tag per approval, so two requests never replace each other', async () => {
    const w = world({ approverSubjects: ['owner'] });
    const row = await w.service.open(w.client as never, 't1', {
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'shell',
      resource: 'x',
      summary: 's',
      highRisk: false,
      toolName: 'Cursor',
    });
    expect(w.push.notifyApprovers).toHaveBeenCalledWith(
      w.client,
      't1',
      expect.objectContaining({ tag: `approval-${row.id}` }),
    );
  });

  it('a vault request is high risk, so the device can never decide it', async () => {
    const w = world({ approverSubjects: ['owner'] });
    const r = await w.controller.vault(host(), {
      program: 'node',
      secret: 'AWS_KEY',
    });
    const row = w.rows.find((x) => x.id === r.id)!;
    expect(row).toMatchObject({
      toolId: 'host.vault',
      actionId: 'secret.use',
      resource: 'AWS_KEY',
      highRisk: true,
    });
    await expect(
      w.controller.decide(host(), r.id, { decision: 'approve_once' }),
    ).rejects.toThrow('high_risk_open_in_console');
  });

  it('make-rule never widens: no draft for a wildcard or prefix resource', () => {
    expect(
      buildRuleDraft({ toolId: 't', actionId: 'a', resource: '*' }),
    ).toBeNull();
    expect(
      buildRuleDraft({ toolId: 't', actionId: 'a', resource: 'repo/x:*' }),
    ).toBeNull();
    expect(
      buildRuleDraft({ toolId: 't', actionId: 'a', resource: 'repo/x' }),
    ).not.toBeNull();
  });
});

describe('during a pause', () => {
  it('refuses to approve inside the transaction, but a deny still goes through', async () => {
    const w = world({ approverSubjects: ['alice'], paused: true });
    await expect(
      w.service.decide(w.client as never, 't1', {
        approvalId: 'ap1',
        subject: 'alice',
        decision: 'approve_once',
        via: 'console',
      }),
    ).rejects.toMatchObject({ status: 409 });
    expect(w.rows[0]?.status).toBe('PENDING');
    const r = await w.service.decide(w.client as never, 't1', {
      approvalId: 'ap1',
      subject: 'alice',
      decision: 'deny',
      via: 'console',
    });
    expect(r.status).toBe('DENIED');
  });

  it('opens nothing new', async () => {
    const w = world({ approverSubjects: [], paused: true });
    await expect(
      w.service.open(w.client as never, 't1', {
        hostId: 'h9',
        toolId: 'host.cursor',
        actionId: 'edit',
        resource: '/x',
        summary: 's',
        highRisk: false,
        toolName: 'Cursor',
      }),
    ).rejects.toMatchObject({ status: 403 });
  });
});
