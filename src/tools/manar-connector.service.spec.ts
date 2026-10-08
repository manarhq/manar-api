import { describe, expect, it, vi } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditService } from '../audit/audit.service';
import { GrantableToolActionSchema } from '../authorization/grant-triples';
import { CreateTaskRequestSchema } from '../tasks/tasks.validation';
import { AgentQuarantineService } from '../kill-switches/agent-quarantine.service';
import { ManarConnectorService } from './manar-connector.service';

type Row = Record<string, unknown>;

/** In-memory `agent` + `agentQuarantine` honouring the WHERE clauses the service uses. */
function fakeTenant(agentIds: string[]) {
  const rows: Row[] = [];
  const matches = (row: Row, where: Row) =>
    Object.entries(where).every(([k, v]) => row[k] === v);
  const client = {
    agent: {
      findUnique: vi.fn(({ where }: { where: { id: string } }) =>
        Promise.resolve(agentIds.includes(where.id) ? { id: where.id } : null),
      ),
    },
    agentQuarantine: {
      updateMany: vi.fn(({ where, data }: { where: Row; data: Row }) => {
        const hit = rows.filter((r) => matches(r, where));
        hit.forEach((r) => Object.assign(r, data));
        return Promise.resolve({ count: hit.length });
      }),
      create: vi.fn(({ data }: { data: Row }) => {
        if (rows.some((r) => r.agentId === data.agentId)) {
          return Promise.reject(
            Object.assign(new Error('dup'), { code: 'P2002' }),
          );
        }
        const row = { id: `q-${rows.length + 1}`, ...data };
        rows.push(row);
        return Promise.resolve(row);
      }),
      findUniqueOrThrow: vi.fn(({ where }: { where: Row }) =>
        Promise.resolve(rows.find((r) => matches(r, where))),
      ),
      update: vi.fn(({ where, data }: { where: Row; data: Row }) => {
        const row = rows.find((r) => matches(r, where))!;
        return Promise.resolve(Object.assign(row, data));
      }),
    },
  } as unknown as TenantPrismaClient;
  return { client, rows };
}

function harness(agentIds = ['target-1', 'watcher-1']) {
  const recordSafely = vi.fn().mockResolvedValue(undefined);
  const record = vi.fn().mockResolvedValue({});
  const audit = { recordSafely, record } as unknown as AuditService;
  const quarantine = new AgentQuarantineService(audit);
  const connector = new ManarConnectorService(quarantine);
  const tenant = fakeTenant(agentIds);
  const call = (actionId: string, resource: string, params: unknown) =>
    connector.invoke(tenant.client, {
      tenantId: 'tenant-1',
      taskId: 'task-w',
      agentId: 'watcher-1',
      actionId,
      resource,
      params,
      decisionId: 'decision-1',
    });
  return { call, quarantine, tenant, recordSafely, record };
}

describe('Manar connector: manar.agent.quarantine (ADR-0009)', () => {
  it('quarantines once, audits agent.quarantined with the watcher as actor, and is idempotent', async () => {
    const h = harness();
    const first = await h.call('manar.agent.quarantine', 'target-1', {
      reason: 'burst of denied actions',
      detector: 'deny_burst',
      evidence: ['d-1', 'd-2'],
    });
    expect(first).toMatchObject({
      success: true,
      data: { result: 'quarantined', agentId: 'target-1' },
    });
    const second = await h.call('manar.agent.quarantine', 'target-1', {
      reason: 'again',
    });
    expect(second).toMatchObject({
      success: true,
      data: { result: 'already_quarantined', explanationAttached: false },
    });
    expect(h.tenant.rows).toHaveLength(1);
    expect(h.tenant.rows[0]).toMatchObject({
      active: true,
      reason: 'burst of denied actions',
      quarantinedByAgentId: 'watcher-1',
      decisionId: 'decision-1',
    });
    const events = h.recordSafely.mock.calls.map(
      (c) => (c[2] as { eventType: string }).eventType,
    );
    expect(events).toEqual([AUDIT_EVENT_TYPES.AGENT_QUARANTINED]);
    expect(h.recordSafely.mock.calls[0]![2]).toMatchObject({
      actor: { type: 'agent', id: 'watcher-1' },
      data: { targetAgentId: 'target-1', evidence: ['d-1', 'd-2'] },
    });
  });

  it('attaches the explanation once and never rewrites it', async () => {
    const h = harness();
    await h.call('manar.agent.quarantine', 'target-1', { reason: 'r' });
    const explanation = {
      en: 'It disabled many users.',
      ar: 'عطّل مستخدمين كثيرين.',
    };
    const attach = await h.call('manar.agent.quarantine', 'target-1', {
      reason: 'r',
      explanation,
    });
    expect(attach).toMatchObject({ data: { explanationAttached: true } });
    const rewrite = await h.call('manar.agent.quarantine', 'target-1', {
      reason: 'r',
      explanation: { en: 'something else', ar: 'شيء آخر' },
    });
    expect(rewrite).toMatchObject({ data: { explanationAttached: false } });
    expect(h.tenant.rows[0]).toMatchObject({
      explanationEn: explanation.en,
      explanationAr: explanation.ar,
    });
  });

  it('cannot target an agent outside this tenant database', async () => {
    const h = harness();
    const result = await h.call(
      'manar.agent.quarantine',
      'other-tenant-agent',
      {
        reason: 'r',
      },
    );
    expect(result).toEqual({ success: false, errorMessage: 'agent_not_found' });
    expect(h.tenant.rows).toHaveLength(0);
  });

  it('rejects anything but the documented params (no smuggled "active: false")', async () => {
    const h = harness();
    for (const params of [
      { reason: 'r', active: false },
      { reason: '' },
      { reason: 'r', evidence: ['not an id!'] },
      {},
    ]) {
      expect(
        await h.call('manar.agent.quarantine', 'target-1', params),
      ).toEqual({ success: false, errorMessage: 'invalid_params' });
    }
  });

  it('has no release or any other action: unknown names never run', async () => {
    const h = harness();
    for (const actionId of [
      'manar.agent.release',
      'manar.agent.deactivate',
      'manar.killswitch.deactivate',
      'manar.approval.decide',
    ]) {
      expect(await h.call(actionId, 'target-1', {})).toEqual({
        success: false,
        errorMessage: 'unknown_manar_action',
      });
    }
  });

  it('release (human path) reverts if the audit event cannot be written', async () => {
    const h = harness();
    await h.call('manar.agent.quarantine', 'target-1', { reason: 'r' });
    h.record.mockRejectedValueOnce(new Error('audit down'));
    await expect(
      h.quarantine.release(h.tenant.client, 'tenant-1', {
        agentId: 'target-1',
        releasedBy: 'human-1',
      }),
    ).rejects.toThrow();
    expect(h.tenant.rows[0]).toMatchObject({ active: true, releasedBy: null });

    const released = await h.quarantine.release(h.tenant.client, 'tenant-1', {
      agentId: 'target-1',
      releasedBy: 'human-1',
      note: 'checked',
    });
    expect(released).toMatchObject({ active: false, releasedBy: 'human-1' });
    expect(h.record).toHaveBeenLastCalledWith(
      h.tenant.client,
      'tenant-1',
      expect.objectContaining({
        eventType: AUDIT_EVENT_TYPES.AGENT_QUARANTINE_RELEASED,
        actor: { type: 'human', id: 'human-1' },
      }),
    );
  });
});

describe('Manar connector: no agent can be granted a loosening capability', () => {
  it('only the catalog actions are grantable on tool "manar"', () => {
    for (const actionId of ['manar.activity.read', 'manar.agent.quarantine']) {
      expect(
        GrantableToolActionSchema.safeParse({ toolId: 'manar', actionId })
          .success,
      ).toBe(true);
    }
    for (const actionId of [
      'manar.agent.release',
      'manar.agent.unquarantine',
      'manar.killswitch.deactivate',
      'manar.approval.approve',
    ]) {
      expect(
        GrantableToolActionSchema.safeParse({ toolId: 'manar', actionId })
          .success,
      ).toBe(false);
    }
  });

  it('task creation rejects a release grant but may forbid one', () => {
    const base = {
      name: 'watcher',
      assignedAgentId: 'agent-1',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    expect(
      CreateTaskRequestSchema.safeParse({
        ...base,
        allowedToolActions: [
          { toolId: 'manar', actionId: 'manar.agent.quarantine' },
          { toolId: 'manar', actionId: 'manar.agent.release' },
        ],
      }).success,
    ).toBe(false);
    expect(
      CreateTaskRequestSchema.safeParse({
        ...base,
        allowedToolActions: [
          { toolId: 'manar', actionId: 'manar.agent.quarantine' },
        ],
        forbiddenActions: [
          { toolId: 'manar', actionId: 'manar.agent.release' },
        ],
      }).success,
    ).toBe(true);
  });
});

describe('Manar connector: manar.activity.read returns metadata only', () => {
  it('hashes resources and returns no parameters', async () => {
    const decisions = [
      {
        id: 'd-1',
        agentId: 'a-1',
        taskId: 't-1',
        toolId: 'iam',
        actionId: 'disable-user',
        resource: 'alice@example.test',
        outcome: 'DENY',
        reasonCodes: ['policy_denied'],
        stage: 'REQUEST',
        createdAt: new Date(),
      },
    ];
    const findMany = (rows: unknown[]) => vi.fn().mockResolvedValue(rows);
    const decisionFindMany = vi.fn<
      (query: { select: Row }) => Promise<typeof decisions>
    >(() => Promise.resolve(decisions));
    const client = {
      decision: {
        findMany: decisionFindMany,
        groupBy: vi.fn().mockResolvedValue([]),
      },
      approvalRequest: { findMany: findMany([]) },
      toolInvocation: { findMany: findMany([]) },
      agent: { findMany: findMany([]) },
      toolAction: {
        findMany: findMany([
          {
            name: 'disable-user',
            mutating: true,
            destructive: true,
            tool: { name: 'iam' },
          },
        ]),
      },
    } as unknown as TenantPrismaClient;
    const connector = new ManarConnectorService({} as AgentQuarantineService);
    const result = await connector.invoke(client, {
      tenantId: 'tenant-1',
      taskId: 'task-w',
      agentId: 'watcher-1',
      actionId: 'manar.activity.read',
      resource: 'tenant',
      params: { windowSeconds: 60 },
      decisionId: 'decision-1',
    });
    expect(result.success).toBe(true);
    const text = JSON.stringify(result.data);
    expect(text).not.toContain('alice@example.test');
    expect(text).not.toContain('params');
    expect((result.data as { decisions: Row[] }).decisions[0]).toMatchObject({
      actionId: 'disable-user',
      outcome: 'DENY',
      reason: 'policy_denied',
      destructive: true,
      resourceRef: expect.stringMatching(/^[0-9a-f]{16}$/) as string,
    });
    // The select never asks for inputsHash or params.
    const select = decisionFindMany.mock.calls[0]![0].select;
    expect(Object.keys(select)).not.toContain('inputsHash');
    expect(
      await connector.invoke(client, {
        tenantId: 'tenant-1',
        taskId: 'task-w',
        agentId: 'watcher-1',
        actionId: 'manar.activity.read',
        resource: 'tenant',
        params: { windowSeconds: 999_999 },
        decisionId: 'decision-1',
      }),
    ).toEqual({ success: false, errorMessage: 'invalid_params' });
  });
});
