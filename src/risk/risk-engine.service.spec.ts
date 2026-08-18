import { describe, expect, it } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { TaskGrantSyncService } from '../authorization/task-grant-sync.service';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import { RiskEngine } from './risk-engine.service';

function makeTask(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return {
    id: 'task-1',
    parentTaskId: null,
    requesterId: 'user-1',
    assignedAgentId: 'agent-1',
    status: 'ACTIVE',
    startsAt: new Date(),
    expiresAt: new Date(Date.now() + 3_600_000),
    maxExecutions: null,
    executionCount: 0,
    allowedToolActions: [],
    allowedResourceSelectors: [],
    forbiddenActions: [],
    riskCeiling: 20,
    ...overrides,
  };
}

/** A fake tenantClient backing `TasksService.getAncestorChain` — a plain in-memory map of task rows keyed by id, no real database. */
function fakeTenantClient(
  tasksById: Record<string, TaskRecord>,
): TenantPrismaClient {
  return {
    task: {
      findUnique: ({ where: { id } }: { where: { id: string } }) =>
        Promise.resolve(tasksById[id] ?? null),
    },
  } as unknown as TenantPrismaClient;
}

describe('RiskEngine', () => {
  const tasksService = new TasksService({} as TaskGrantSyncService);

  it('scores a root task with an innocuous action at the baseline', async () => {
    const engine = new RiskEngine(tasksService);
    const task = makeTask();
    const result = await engine.score(fakeTenantClient({ [task.id]: task }), {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
      task,
    });
    expect(result.deterministicRiskScore).toBe(10);
    expect(result.finalRiskScore).toBe(10);
    expect(result.aiAdvisoryScore).toBeNull();
    expect(result.reasonCodes).toEqual(['baseline_risk:10']);
  });

  it('adds points for delegation depth, reusing the real ancestor-chain walk', async () => {
    const root = makeTask({ id: 'root' });
    const child = makeTask({ id: 'child', parentTaskId: 'root' });
    const grandchild = makeTask({ id: 'grandchild', parentTaskId: 'child' });
    const client = fakeTenantClient({ root, child, grandchild });

    const engine = new RiskEngine(tasksService);
    const result = await engine.score(client, {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
      task: grandchild,
    });
    // baseline 10 + depth(2 ancestors * 5) = 20
    expect(result.deterministicRiskScore).toBe(20);
    expect(result.reasonCodes).toContain('delegation_depth:2:10');
  });

  it('adds points for a destructive-keyword actionId', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService);
    const result = await engine.score(fakeTenantClient({ [task.id]: task }), {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
      task,
    });
    // baseline 10 + destructive keyword 25 = 35
    expect(result.deterministicRiskScore).toBe(35);
    expect(
      result.reasonCodes.some((c) => c.startsWith('destructive_keyword:')),
    ).toBe(true);
  });

  it('adds the matched policy rule riskWeight', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService);
    const result = await engine.score(fakeTenantClient({ [task.id]: task }), {
      toolId: 'iam',
      actionId: 'update_role',
      resource: 'role-1',
      task,
      policyMatch: { riskWeight: 40 },
    });
    // baseline 10 + riskWeight 40 = 50
    expect(result.deterministicRiskScore).toBe(50);
  });

  it('clamps up to riskFloor when the additive sum is lower', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService);
    const result = await engine.score(fakeTenantClient({ [task.id]: task }), {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
      task,
      policyMatch: { riskFloor: 90 },
    });
    expect(result.deterministicRiskScore).toBe(90);
    expect(result.reasonCodes).toContain('policy_risk_floor:90');
  });

  it('never exceeds 100', async () => {
    const root = makeTask({ id: 'root' });
    const deep = makeTask({ id: 'deep', parentTaskId: 'root' });
    const engine = new RiskEngine(tasksService);
    const result = await engine.score(fakeTenantClient({ root, deep }), {
      toolId: 'iam',
      actionId: 'delete_all_users',
      resource: '*',
      task: deep,
      policyMatch: { riskWeight: 100 },
    });
    expect(result.deterministicRiskScore).toBe(100);
  });
});
