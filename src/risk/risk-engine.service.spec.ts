import { describe, expect, it } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { TaskGrantSyncService } from '../authorization/task-grant-sync.service';
import type { AuditService } from '../audit/audit.service';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import { ToolRegistryService } from '../tools/tool-registry.service';
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

interface FakeToolRow {
  id: string;
  name: string;
  credentialReference?: unknown;
}
interface FakeToolActionRow {
  toolId: string;
  name: string;
  riskBaseScore: number;
  mutating?: boolean;
  destructive?: boolean;
}

/**
 * A fake tenantClient backing `TasksService.getAncestorChain` (a plain
 * in-memory map of task rows keyed by id) and, since Phase 7b,
 * `ToolRegistryService.findToolAction` (plain in-memory `tool`/
 * `toolAction` rows) — no real database. `tools`/`toolActions` default to
 * empty, matching the common case of a `{toolId, actionId}` pair with no
 * registered `ToolAction` at all (see `RiskEngine`'s own doc comment for
 * why that's a normal "contributes nothing" outcome, not an error).
 */
function fakeTenantClient(options: {
  tasksById: Record<string, TaskRecord>;
  tools?: FakeToolRow[];
  toolActions?: FakeToolActionRow[];
}): TenantPrismaClient {
  const tools = options.tools ?? [];
  const toolActions = options.toolActions ?? [];
  return {
    task: {
      findUnique: ({ where: { id } }: { where: { id: string } }) =>
        Promise.resolve(options.tasksById[id] ?? null),
    },
    tool: {
      findUnique: ({ where: { name } }: { where: { name: string } }) =>
        Promise.resolve(
          tools.find((t) => t.name === name)
            ? {
                credentialReference: { provider: 'ENV', reference: 'X' },
                type: 'TEST',
                vendor: null,
                description: null,
                baseEndpoint: 'http://example.test',
                protocol: 'HTTP',
                enabled: true,
                metadata: {},
                ...tools.find((t) => t.name === name),
              }
            : null,
        ),
    },
    toolAction: {
      findUnique: ({
        where: { toolId_name },
      }: {
        where: { toolId_name: { toolId: string; name: string } };
      }) =>
        Promise.resolve(
          toolActions.find(
            (a) =>
              a.toolId === toolId_name.toolId && a.name === toolId_name.name,
          )
            ? {
                id: 'action-id',
                description: null,
                inputSchema: null,
                outputSchema: null,
                mutating: false,
                destructive: false,
                approvalDefault: false,
                ...toolActions.find(
                  (a) =>
                    a.toolId === toolId_name.toolId &&
                    a.name === toolId_name.name,
                ),
              }
            : null,
        ),
    },
  } as unknown as TenantPrismaClient;
}

describe('RiskEngine', () => {
  const tasksService = new TasksService(
    {} as TaskGrantSyncService,
    {
      recordSafely: () => Promise.resolve(undefined),
    } as unknown as AuditService,
  );
  const toolRegistry = new ToolRegistryService();

  it('scores a root task with an innocuous action at the baseline', async () => {
    const engine = new RiskEngine(tasksService, toolRegistry);
    const task = makeTask();
    const result = await engine.score(
      fakeTenantClient({ tasksById: { [task.id]: task } }),
      { toolId: 'fs', actionId: 'read', resource: 'anything', task },
    );
    expect(result.deterministicRiskScore).toBe(10);
    expect(result.finalRiskScore).toBe(10);
    expect(result.aiAdvisoryScore).toBeNull();
    expect(result.reasonCodes).toEqual(['baseline_risk:10']);
  });

  it('adds points for delegation depth, reusing the real ancestor-chain walk', async () => {
    const root = makeTask({ id: 'root' });
    const child = makeTask({ id: 'child', parentTaskId: 'root' });
    const grandchild = makeTask({ id: 'grandchild', parentTaskId: 'child' });
    const client = fakeTenantClient({
      tasksById: { root, child, grandchild },
    });

    const engine = new RiskEngine(tasksService, toolRegistry);
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

  it('a {toolId, actionId} pair with no registered ToolAction contributes nothing beyond the baseline', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService, toolRegistry);
    const result = await engine.score(
      fakeTenantClient({ tasksById: { [task.id]: task } }),
      {
        toolId: 'edr',
        actionId: 'isolate_host',
        resource: 'host-1',
        task,
      },
    );
    expect(result.deterministicRiskScore).toBe(10);
    expect(result.reasonCodes).toEqual(['baseline_risk:10']);
  });

  it('adds a registered ToolAction.riskBaseScore', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService, toolRegistry);
    const client = fakeTenantClient({
      tasksById: { [task.id]: task },
      tools: [{ id: 'tool-1', name: 'edr' }],
      toolActions: [
        { toolId: 'tool-1', name: 'isolate_host', riskBaseScore: 30 },
      ],
    });
    const result = await engine.score(client, {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
      task,
    });
    // baseline 10 + riskBaseScore 30 = 40
    expect(result.deterministicRiskScore).toBe(40);
    expect(result.reasonCodes).toContain('tool_action_risk_base:30');
  });

  it('adds mutating and destructive contributions independently, on top of riskBaseScore', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService, toolRegistry);
    const client = fakeTenantClient({
      tasksById: { [task.id]: task },
      tools: [{ id: 'tool-1', name: 'edr' }],
      toolActions: [
        {
          toolId: 'tool-1',
          name: 'isolate_host',
          riskBaseScore: 20,
          mutating: true,
          destructive: true,
        },
      ],
    });
    const result = await engine.score(client, {
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
      task,
    });
    // baseline 10 + riskBaseScore 20 + mutating 15 + destructive 25 = 70
    expect(result.deterministicRiskScore).toBe(70);
    expect(result.reasonCodes).toContain('tool_action_risk_base:20');
    expect(result.reasonCodes).toContain('tool_action_mutating:15');
    expect(result.reasonCodes).toContain('tool_action_destructive:25');
  });

  it('adds the matched policy rule riskWeight', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService, toolRegistry);
    const result = await engine.score(
      fakeTenantClient({ tasksById: { [task.id]: task } }),
      {
        toolId: 'iam',
        actionId: 'update_role',
        resource: 'role-1',
        task,
        policyMatch: { riskWeight: 40 },
      },
    );
    // baseline 10 + riskWeight 40 = 50
    expect(result.deterministicRiskScore).toBe(50);
  });

  it('clamps up to riskFloor when the additive sum is lower', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService, toolRegistry);
    const result = await engine.score(
      fakeTenantClient({ tasksById: { [task.id]: task } }),
      {
        toolId: 'edr',
        actionId: 'isolate_host',
        resource: 'host-1',
        task,
        policyMatch: { riskFloor: 90 },
      },
    );
    expect(result.deterministicRiskScore).toBe(90);
    expect(result.reasonCodes).toContain('policy_risk_floor:90');
  });

  it('never exceeds 100', async () => {
    const root = makeTask({ id: 'root' });
    const deep = makeTask({ id: 'deep', parentTaskId: 'root' });
    const engine = new RiskEngine(tasksService, toolRegistry);
    const result = await engine.score(
      fakeTenantClient({ tasksById: { root, deep } }),
      {
        toolId: 'iam',
        actionId: 'delete_all_users',
        resource: '*',
        task: deep,
        policyMatch: { riskWeight: 100 },
      },
    );
    expect(result.deterministicRiskScore).toBe(100);
  });
});
