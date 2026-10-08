import { describe, expect, it } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { AgentsService } from '../agents/agents.service';
import type { AuditService } from '../audit/audit.service';
import type {
  CreateTaskInput,
  TaskRecord,
  TasksService,
} from '../tasks/tasks.service';
import type { KillSwitchService } from '../kill-switches/kill-switch.service';
import {
  DelegationDeniedError,
  DelegationExceedsParentLimitsError,
} from './delegation.errors';
import { DelegationService } from './delegation.service';
import { DelegateTaskRequestSchema } from './delegation.validation';

/**
 * Gate 0 R3: a child task must never get more risk headroom or more
 * executions than its parent has left. Hand-rolled fakes, no database; the
 * grant subset check and the rest of the flow are covered by
 * test/task-delegation.e2e-spec.ts.
 */

const PARENT: TaskRecord = {
  id: 'task-parent',
  name: 'parent',
  description: null,
  parentTaskId: null,
  requesterId: 'user-1',
  assignedAgentId: 'agent-parent',
  status: 'ACTIVE',
  startsAt: new Date('2026-01-01T00:00:00Z'),
  expiresAt: new Date('2099-01-01T00:00:00Z'),
  maxExecutions: 5,
  executionCount: 3,
  allowedToolActions: [],
  allowedResourceSelectors: [],
  forbiddenActions: [],
  riskCeiling: 40,
  createdAt: new Date('2026-01-01T00:00:00Z'),
};

function setup(
  parent: Partial<TaskRecord> = {},
  killSwitch: { killed: boolean; reason?: string } = { killed: false },
) {
  const created: CreateTaskInput[] = [];
  const agentsCreated: unknown[] = [];
  const audited: { data: Record<string, unknown> }[] = [];
  const tasksService = {
    getTaskOrThrow: () => Promise.resolve({ ...PARENT, ...parent }),
    evaluateFullLiveness: () => Promise.resolve({ ok: true }),
    getEffectiveGrantSet: () => Promise.resolve(new Set<string>()),
    resolveRootRequesterId: () => Promise.resolve('user-1'),
    createTask: (_client: unknown, _tenant: string, input: CreateTaskInput) => {
      created.push(input);
      return Promise.resolve({ ...PARENT, id: 'task-child', ...input });
    },
  } as unknown as TasksService;
  const agentsService = {
    createAgent: (input: unknown) => {
      agentsCreated.push(input);
      return Promise.resolve({ id: 'agent-child', slug: 'c', identifier: 'x' });
    },
    createEnrollmentToken: () =>
      Promise.resolve({ rawToken: 't', expiresAt: new Date() }),
  } as unknown as AgentsService;
  const auditService = {
    recordSafely: (
      _client: unknown,
      _tenant: string,
      event: { data: Record<string, unknown> },
    ) => {
      audited.push(event);
      return Promise.resolve();
    },
  } as unknown as AuditService;
  const service = new DelegationService(
    tasksService,
    agentsService,
    auditService,
    {
      checkAll: () => Promise.resolve(killSwitch),
    } as unknown as KillSwitchService,
  );
  const delegate = (body: Record<string, unknown>) =>
    service.delegate(
      {} as TenantPrismaClient,
      'tenant-1',
      'acme',
      PARENT.id,
      'agent-parent',
      DelegateTaskRequestSchema.parse({
        childAgentSlug: 'child',
        name: 'child',
        ...body,
      }),
    );
  return { delegate, created, agentsCreated, audited };
}

describe('DelegationService refuses a stopped caller (ADR-0009, finding 1)', () => {
  for (const reason of ['agent_quarantined', 'agent_kill_switch_active']) {
    it(`${reason}: no child agent, no child task`, async () => {
      const { delegate, created, agentsCreated } = setup(
        {},
        { killed: true, reason },
      );
      await expect(delegate({})).rejects.toMatchObject({
        constructor: DelegationDeniedError,
        reason,
      });
      expect(agentsCreated).toHaveLength(0);
      expect(created).toHaveLength(0);
    });
  }
});

describe('DelegationService limits (R3)', () => {
  it('rejects a riskCeiling above the parent and writes nothing', async () => {
    const { delegate, created, agentsCreated } = setup();
    await expect(delegate({ riskCeiling: 41 })).rejects.toBeInstanceOf(
      DelegationExceedsParentLimitsError,
    );
    expect(agentsCreated).toHaveLength(0);
    expect(created).toHaveLength(0);
  });

  it('rejects maxExecutions above the parent remaining (5 - 3 = 2)', async () => {
    const { delegate, created } = setup();
    await expect(delegate({ maxExecutions: 3 })).rejects.toBeInstanceOf(
      DelegationExceedsParentLimitsError,
    );
    expect(created).toHaveLength(0);
  });

  it('rejects unlimited maxExecutions under a limited parent', async () => {
    const { delegate, created } = setup();
    await expect(delegate({ maxExecutions: null })).rejects.toBeInstanceOf(
      DelegationExceedsParentLimitsError,
    );
    expect(created).toHaveLength(0);
  });

  it('accepts values within the parent limits unchanged', async () => {
    const { delegate, created } = setup();
    await delegate({ riskCeiling: 40, maxExecutions: 2 });
    expect(created[0]).toMatchObject({ riskCeiling: 40, maxExecutions: 2 });
  });

  it('clamps omitted values to the parent and audits them', async () => {
    const { delegate, created, audited } = setup({ riskCeiling: 10 });
    await delegate({});
    expect(created[0]).toMatchObject({ riskCeiling: 10, maxExecutions: 2 });
    expect(audited[0]?.data).toMatchObject({
      riskCeiling: 10,
      maxExecutions: 2,
    });
  });

  it('keeps the default ceiling of 20 when the parent allows more', async () => {
    const { delegate, created } = setup();
    await delegate({});
    expect(created[0]).toMatchObject({ riskCeiling: 20 });
  });

  it('allows unlimited (explicit or omitted) under an unlimited parent', async () => {
    const { delegate, created } = setup({ maxExecutions: null });
    await delegate({ maxExecutions: null });
    await delegate({});
    await delegate({ maxExecutions: 1000 });
    expect(created.map((input) => input.maxExecutions)).toEqual([
      null,
      null,
      1000,
    ]);
  });
});
