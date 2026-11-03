import { describe, expect, it, vi } from 'vitest';
import { ApprovalRevokeService } from './approval-revoke.service';
import { HostApprovalsService } from './host-approvals.service';

type Row = Record<string, unknown> & { id: string };

/** `where` the way Prisma applies it, for the operators these paths use. */
function matches(row: Row, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([k, v]) => {
    const value = row[k] ?? null;
    if (v && typeof v === 'object' && !(v instanceof Date)) {
      const op = v as { gt?: Date };
      if (op.gt) return value instanceof Date && value > op.gt;
      return true;
    }
    return value === v;
  });
}

function table(rows: Row[] = []) {
  return {
    rows,
    findUnique: ({ where }: { where: { id: string } }) =>
      Promise.resolve(rows.find((r) => r.id === where.id) ?? null),
    findFirst: ({ where }: { where: Record<string, unknown> }) =>
      Promise.resolve(rows.find((r) => matches(r, where)) ?? null),
    updateMany: ({
      where,
      data,
    }: {
      where: Record<string, unknown>;
      data: Row;
    }) => {
      const hit = rows.filter((r) => matches(r, where));
      hit.forEach((r) => Object.assign(r, data));
      return Promise.resolve({ count: hit.length });
    },
    deleteMany: ({ where }: { where: Record<string, unknown> }) => {
      const before = rows.length;
      rows.splice(0, rows.length, ...rows.filter((r) => !matches(r, where)));
      return Promise.resolve({ count: before - rows.length });
    },
    create: ({ data }: { data: Omit<Row, 'id'> }) => {
      const r = { id: `new-${rows.length + 1}`, revokedAt: null, ...data };
      rows.push(r);
      return Promise.resolve(r);
    },
    upsert: ({ create }: { create: Omit<Row, 'id'> }) => {
      const r = { id: 'rule-deny', ...create };
      rows.push(r);
      return Promise.resolve(r);
    },
  };
}

const NOW = new Date();
const LATER = new Date(Date.now() + 3_600_000);

function world(host: Partial<Row> = {}, agent: Partial<Row> = {}) {
  const client = {
    $queryRaw: () => Promise.resolve([{ now: NOW }]),
    workspacePause: { findUnique: () => Promise.resolve(null) },
    hostApproval: table([
      {
        id: 'h-ap',
        hostId: 'h1',
        toolId: 'host.cursor',
        actionId: 'shell',
        resource: 'rm -rf build',
        status: 'APPROVED',
        decision: 'approve_8h',
        usedAt: null,
        expiresAt: LATER,
        ...host,
      },
    ]),
    approvalRequest: table([
      {
        id: 'a-ap',
        agentId: 'agent-1',
        toolId: 'gitlab',
        actionId: 'merge',
        resource: 'repo/x',
        status: 'APPROVED',
        releasedAt: null,
        grant: { id: 'grant-1' },
        ...agent,
      },
    ]),
    authorizationGrant: table([
      { id: 'grant-1', consumedAt: null, revokedAt: null },
    ]),
    approvalAllowGrant: table([
      {
        id: 'g8',
        sourceId: 'h-ap',
        effect: 'ALLOW',
        revokedAt: null,
        expiresAt: LATER,
      },
    ]),
    hostSiteRule: table([]),
    incident: table([]),
  };
  const audit = { recordSafely: vi.fn(() => Promise.resolve(true)) };
  const push = { notifyApprovers: vi.fn(() => Promise.resolve(1)) };
  const service = new ApprovalRevokeService(audit as never, push as never);
  const by = { userId: 'u1', subject: 'sub-1' };
  return { client, audit, push, service, by };
}

describe('revoking a device approval', () => {
  it('not yet read by the device: cancelled, nothing ran, the 8-hour grant is withdrawn, no alarm', async () => {
    const w = world();
    const r = await w.service.revokeHost(
      w.client as never,
      't1',
      'h-ap',
      w.by,
      'wrong one',
    );
    expect(r).toMatchObject({
      status: 'REVOKED',
      usedBeforeRevoke: false,
      withdrawn: 1,
      blockId: null,
      incidentId: null,
    });
    expect(w.client.hostApproval.rows[0]).toMatchObject({
      status: 'REVOKED',
      revokedBy: 'sub-1',
      revokeNote: 'wrong one',
    });
    expect(w.client.approvalAllowGrant.rows[0]!.revokedAt).toBeInstanceOf(Date);
    expect(w.client.incident.rows).toHaveLength(0);
    expect(w.push.notifyApprovers).not.toHaveBeenCalled();
  });

  it('already read by the device: revoked after use, blocked next time, and the admins are alerted', async () => {
    const w = world({ usedAt: NOW });
    const r = await w.service.revokeHost(w.client as never, 't1', 'h-ap', w.by);
    expect(r.usedBeforeRevoke).toBe(true);
    const block = w.client.approvalAllowGrant.rows.find(
      (g) => g.effect === 'BLOCK',
    );
    expect(block).toMatchObject({
      hostId: 'h1',
      toolId: 'host.cursor',
      actionId: 'shell',
      resource: 'rm -rf build',
    });
    expect(r.blockId).toBe(block!.id);
    expect(w.client.incident.rows[0]).toMatchObject({
      severity: 'HIGH',
      createdBy: 'u1',
    });
    expect(w.push.notifyApprovers).toHaveBeenCalledWith(
      w.client,
      't1',
      expect.objectContaining({ kind: 'approval_revoked' }),
    );
  });

  it('the device and a revoke racing: whichever lands first decides what the device sees', async () => {
    const w = world();
    const hosts = new HostApprovalsService(
      { recordSafely: vi.fn() } as never,
      { notifyApprovers: vi.fn() } as never,
      {} as never,
    );
    // The device reads first: it saw APPROVED, so the revoke is after use.
    expect(
      (await hosts.readForDevice(w.client as never, 'h-ap', 'h1')).status,
    ).toBe('APPROVED');
    expect(
      (await w.service.revokeHost(w.client as never, 't1', 'h-ap', w.by))
        .usedBeforeRevoke,
    ).toBe(true);

    // The revoke lands first: the device reads REVOKED and never runs it.
    const v = world();
    await v.service.revokeHost(v.client as never, 't1', 'h-ap', v.by);
    const seen = await hosts.readForDevice(v.client as never, 'h-ap', 'h1');
    expect(seen).toMatchObject({ status: 'REVOKED', usedAt: null });
  });

  it('a new site used after "always": its remembered rule goes and a DENY rule takes its place', async () => {
    const w = world({
      actionId: 'site.connect',
      resource: 'evil.example',
      decision: 'approve_always',
      usedAt: NOW,
    });
    w.client.hostSiteRule.rows.push({
      id: 'allow-rule',
      hostId: 'h1',
      toolId: 'host.cursor',
      site: 'evil.example',
      source: 'approval',
      mode: 'ALLOW',
    });
    const r = await w.service.revokeHost(w.client as never, 't1', 'h-ap', w.by);
    expect(
      w.client.hostSiteRule.rows.find((x) => x.id === 'allow-rule'),
    ).toBeUndefined();
    expect(w.client.hostSiteRule.rows).toContainEqual(
      expect.objectContaining({ mode: 'DENY', site: 'evil.example' }),
    );
    expect(r.blockId).toBe('rule-deny');
  });

  it('only an approved request can be revoked', async () => {
    const w = world({ status: 'DENIED' });
    await expect(
      w.service.revokeHost(w.client as never, 't1', 'h-ap', w.by),
    ).rejects.toMatchObject({ response: { reason: 'not_approved' } });
  });
});

describe('revoking an agent approval', () => {
  it('not yet received by the agent: the one-use grant is revoked and nothing ran', async () => {
    const w = world();
    const r = await w.service.revokeAgent(
      w.client as never,
      't1',
      'a-ap',
      w.by,
    );
    expect(r).toMatchObject({ usedBeforeRevoke: false, blockId: null });
    expect(w.client.authorizationGrant.rows[0]!.revokedAt).toBeInstanceOf(Date);
    expect(w.client.approvalRequest.rows[0]).toMatchObject({
      status: 'REVOKED',
      revokedBy: 'u1',
    });
  });

  it('already received by the agent: revoked after use, the agent is blocked from it next time', async () => {
    const w = world({}, { releasedAt: NOW });
    const r = await w.service.revokeAgent(
      w.client as never,
      't1',
      'a-ap',
      w.by,
    );
    expect(r.usedBeforeRevoke).toBe(true);
    expect(w.client.approvalAllowGrant.rows).toContainEqual(
      expect.objectContaining({
        effect: 'BLOCK',
        agentId: 'agent-1',
        toolId: 'gitlab',
        resource: 'repo/x',
      }),
    );
    expect(w.client.incident.rows).toHaveLength(1);
  });

  it('a grant already redeemed over MCP counts as used even if nobody polled', async () => {
    const w = world();
    w.client.authorizationGrant.rows[0]!.consumedAt = NOW;
    const r = await w.service.revokeAgent(
      w.client as never,
      't1',
      'a-ap',
      w.by,
    );
    expect(r.usedBeforeRevoke).toBe(true);
  });
});

describe('standing permissions', () => {
  it('an 8-hour grant can be withdrawn at any time, once', async () => {
    const w = world();
    await w.service.revokeGrant(w.client as never, 't1', 'g8', w.by);
    expect(w.client.approvalAllowGrant.rows[0]!.revokedAt).toBeInstanceOf(Date);
    await expect(
      w.service.revokeGrant(w.client as never, 't1', 'g8', w.by),
    ).rejects.toMatchObject({ status: 409 });
  });
});
