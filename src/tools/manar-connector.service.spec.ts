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
  const matches = (row: Row, where: Row): boolean =>
    Object.entries(where).every(([k, v]) => {
      if (k === 'NOT') return !matches(row, v as Row);
      if (v && typeof v === 'object' && 'gt' in v) {
        return (row[k] as Date) > (v as { gt: Date }).gt;
      }
      return row[k] === v;
    });
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
        const row = {
          id: `00000000-0000-4000-8000-00000000000${rows.length + 1}`,
          ...data,
        };
        rows.push(row);
        return Promise.resolve(row);
      }),
      findUniqueOrThrow: vi.fn(({ where }: { where: Row }) =>
        Promise.resolve(rows.find((r) => matches(r, where))),
      ),
      findUnique: vi.fn(({ where }: { where: Row }) =>
        Promise.resolve(rows.find((r) => matches(r, where)) ?? null),
      ),
      count: vi.fn(async ({ where }: { where: Row }) => {
        const n = rows.filter((r) => matches(r, where)).length;
        await new Promise((r) => setTimeout(r, 2)); // let concurrent calls interleave
        return n;
      }),
      update: vi.fn(({ where, data }: { where: Row; data: Row }) => {
        const row = rows.find((r) => matches(r, where))!;
        return Promise.resolve(Object.assign(row, data));
      }),
    },
  } as unknown as TenantPrismaClient;
  // Interactive transactions run against the same in-memory state; a
  // `pg_advisory_xact_lock(hashtext(key))` is a per-key mutex held until the
  // transaction callback settles, as in PostgreSQL.
  const locks = new Map<string, Promise<void>>();
  (client as unknown as { $transaction: unknown }).$transaction = async (
    fn: (tx: TenantPrismaClient) => Promise<unknown>,
  ) => {
    const releases: (() => void)[] = [];
    const tx = Object.create(client) as Record<string, unknown>;
    tx.$queryRaw = async (_strings: TemplateStringsArray, key: string) => {
      const previous = locks.get(key) ?? Promise.resolve();
      let release!: () => void;
      const mine = new Promise<void>((r) => (release = r));
      locks.set(
        key,
        previous.then(() => mine),
      );
      await previous;
      releases.push(release);
      return [{ '?column?': 1 }];
    };
    try {
      return await fn(tx as unknown as TenantPrismaClient);
    } finally {
      releases.forEach((r) => r());
    }
  };
  return { client, rows };
}

function harness(
  agentIds = ['target-1', 'watcher-1'],
  config: Record<string, unknown> = {},
) {
  const recordSafely = vi.fn().mockResolvedValue(undefined);
  const record = vi.fn().mockResolvedValue({});
  const audit = { recordSafely, record } as unknown as AuditService;
  const quarantine = new AgentQuarantineService(audit, {
    get: (key: string) => config[key],
  } as never);
  const connector = new ManarConnectorService(quarantine);
  const tenant = fakeTenant(agentIds);
  const call = (
    actionId: string,
    resource: string,
    params: unknown,
    agentId = 'watcher-1',
  ) =>
    connector.invoke(tenant.client, {
      tenantId: 'tenant-1',
      taskId: 'task-w',
      agentId,
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

  it('attach-only mode: once, by the quarantining agent, never rewritten', async () => {
    const h = harness(['target-1', 'watcher-1', 'other-watcher']);
    const first = await h.call('manar.agent.quarantine', 'target-1', {
      reason: 'r',
    });
    const quarantineId = (first.data as { quarantineId: string }).quarantineId;
    const explanation = {
      en: 'It disabled many users.',
      ar: 'عطّل مستخدمين كثيرين.',
    };
    // Another agent cannot attach to this quarantine.
    expect(
      await h.call(
        'manar.agent.quarantine',
        'target-1',
        { quarantineId, explanation },
        'other-watcher',
      ),
    ).toMatchObject({ data: { result: 'not_attached' } });
    expect(
      await h.call('manar.agent.quarantine', 'target-1', {
        quarantineId,
        explanation,
      }),
    ).toMatchObject({ data: { result: 'explanation_attached' } });
    expect(
      await h.call('manar.agent.quarantine', 'target-1', {
        quarantineId,
        explanation: { en: 'something else', ar: 'شيء آخر' },
      }),
    ).toMatchObject({ data: { result: 'not_attached' } });
    expect(h.tenant.rows[0]).toMatchObject({
      explanationEn: explanation.en,
      explanationAr: explanation.ar,
    });
  });

  it('an explanation arriving after a human release does not re-quarantine (finding 2)', async () => {
    const h = harness();
    const first = await h.call('manar.agent.quarantine', 'target-1', {
      reason: 'r',
    });
    const quarantineId = (first.data as { quarantineId: string }).quarantineId;
    await h.quarantine.release(h.tenant.client, 'tenant-1', {
      agentId: 'target-1',
      releasedBy: 'human-1',
    });
    const late = await h.call('manar.agent.quarantine', 'target-1', {
      quarantineId,
      explanation: { en: 'late', ar: 'متأخر' },
    });
    expect(late).toMatchObject({ data: { result: 'not_attached' } });
    expect(h.tenant.rows[0]).toMatchObject({
      active: false,
      releasedBy: 'human-1',
    });
    // The old combined form (reason + explanation) is no longer an attach:
    // a plain quarantine call never edits an active one.
    await h.call('manar.agent.quarantine', 'target-1', { reason: 'again' });
    expect(
      await h.call('manar.agent.quarantine', 'target-1', {
        reason: 'r',
        explanation: { en: 'x', ar: 'س' },
      }),
    ).toMatchObject({
      data: { result: 'already_quarantined', explanationAttached: false },
    });
  });

  it('the cap holds under concurrency: cap + 3 parallel calls, exactly cap land', async () => {
    const targets = ['t-1', 't-2', 't-3', 't-4', 't-5'];
    const h = harness([...targets, 'watcher-1'], {
      QUARANTINE_MAX_PER_AGENT: 2,
    });
    const results = await Promise.all(
      targets.map((t) =>
        h.call('manar.agent.quarantine', t, { reason: 'parallel' }),
      ),
    );
    expect(results.filter((r) => r.success)).toHaveLength(2);
    expect(
      results.filter((r) => r.errorMessage === 'quarantine_rate_exceeded'),
    ).toHaveLength(3);
  });

  it('parallel calls on one target: one quarantine, one audit event', async () => {
    const h = harness();
    const results = await Promise.all(
      [1, 2, 3].map(() =>
        h.call('manar.agent.quarantine', 'target-1', { reason: 'same' }),
      ),
    );
    expect(
      results.map((r) => (r.data as { result: string }).result).sort(),
    ).toEqual(['already_quarantined', 'already_quarantined', 'quarantined']);
    expect(h.recordSafely).toHaveBeenCalledTimes(1);
  });

  it('caps how many agents one agent can quarantine per window (finding 3)', async () => {
    const targets = ['t-1', 't-2', 't-3'];
    const h = harness([...targets, 'watcher-1'], {
      QUARANTINE_MAX_PER_AGENT: 2,
    });
    expect(
      await h.call('manar.agent.quarantine', 't-1', { reason: 'r' }),
    ).toMatchObject({ success: true });
    expect(
      await h.call('manar.agent.quarantine', 't-2', { reason: 'r' }),
    ).toMatchObject({ success: true });
    expect(
      await h.call('manar.agent.quarantine', 't-3', { reason: 'r' }),
    ).toEqual({
      success: false,
      errorMessage: 'quarantine_rate_exceeded',
    });
    // Re-asking for one already quarantined is not a new one.
    expect(
      await h.call('manar.agent.quarantine', 't-1', { reason: 'r' }),
    ).toMatchObject({
      data: { result: 'already_quarantined' },
    });
    expect(h.tenant.rows.filter((r) => r.active)).toHaveLength(2);
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
