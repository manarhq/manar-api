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
    name: 'Test task',
    description: null,
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
    createdAt: new Date(),
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
  /** Phase 15a — defaults to `'INTERNAL'` (the real schema default) when omitted, matching every pre-existing test's implicit expectation of "no classification signal beyond the default." */
  classification?: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
}
interface FakeAgentRiskFlagRow {
  agentId: string;
  reason: string;
  expiresAt: Date;
}

/**
 * A fake tenantClient backing `TasksService.getAncestorChain` (a plain
 * in-memory map of task rows keyed by id), `ToolRegistryService.findToolAction`
 * (plain in-memory `tool`/`toolAction` rows), and, since Phase 10b,
 * `tenantClient.agentRiskFlag.findFirst` (plain in-memory rows) — no real
 * database. `tools`/`toolActions`/`agentRiskFlags` default to empty,
 * matching the common case of no registered metadata at all (see
 * `RiskEngine`'s own doc comment for why that's a normal "contributes
 * nothing" outcome, not an error).
 */
function fakeTenantClient(options: {
  tasksById: Record<string, TaskRecord>;
  tools?: FakeToolRow[];
  toolActions?: FakeToolActionRow[];
  agentRiskFlags?: FakeAgentRiskFlagRow[];
}): TenantPrismaClient {
  const tools = options.tools ?? [];
  const toolActions = options.toolActions ?? [];
  const agentRiskFlags = options.agentRiskFlags ?? [];
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
                classification: 'INTERNAL',
                ...toolActions.find(
                  (a) =>
                    a.toolId === toolId_name.toolId &&
                    a.name === toolId_name.name,
                ),
              }
            : null,
        ),
    },
    agentRiskFlag: {
      findFirst: ({
        where,
      }: {
        where: { agentId: string; expiresAt: { gt: Date } };
      }) => {
        const now = where.expiresAt.gt;
        const matches = agentRiskFlags
          .filter((f) => f.agentId === where.agentId && f.expiresAt > now)
          .sort((a, b) => b.expiresAt.getTime() - a.expiresAt.getTime());
        return Promise.resolve(matches[0] ?? null);
      },
    },
  } as unknown as TenantPrismaClient;
}

/** A fake `AiAdvisoryClient` returning a fixed (or `null`) advisory — never makes a real gRPC call. */
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
      {
        toolId: 'fs',
        actionId: 'read',
        resource: 'anything',
        task,
        agentId: 'agent-1',
        tenantId: 'tenant-1',
      },
    );
    expect(result.riskScore).toBe(10);
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
      agentId: 'agent-1',
      tenantId: 'tenant-1',
    });
    // baseline 10 + depth(2 ancestors * 5) = 20
    expect(result.riskScore).toBe(20);
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
        agentId: 'agent-1',
        tenantId: 'tenant-1',
      },
    );
    expect(result.riskScore).toBe(10);
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
      agentId: 'agent-1',
      tenantId: 'tenant-1',
    });
    // baseline 10 + riskBaseScore 30 = 40
    expect(result.riskScore).toBe(40);
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
      agentId: 'agent-1',
      tenantId: 'tenant-1',
    });
    // baseline 10 + riskBaseScore 20 + mutating 15 + destructive 25 = 70
    expect(result.riskScore).toBe(70);
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
        agentId: 'agent-1',
        tenantId: 'tenant-1',
        policyMatch: { riskWeight: 40 },
      },
    );
    // baseline 10 + riskWeight 40 = 50
    expect(result.riskScore).toBe(50);
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
        agentId: 'agent-1',
        tenantId: 'tenant-1',
        policyMatch: { riskFloor: 90 },
      },
    );
    expect(result.riskScore).toBe(90);
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
        agentId: 'agent-1',
        tenantId: 'tenant-1',
        policyMatch: { riskWeight: 100 },
      },
    );
    expect(result.riskScore).toBe(100);
  });

  it('an active AgentRiskFlag applies a fixed bump to deterministicRiskScore, via a plain DB lookup (no AI call)', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService, toolRegistry);
    const client = fakeTenantClient({
      tasksById: { [task.id]: task },
      agentRiskFlags: [
        {
          agentId: 'agent-1',
          reason: 'prompt_injection_detected:edr/isolate_host',
          expiresAt: new Date(Date.now() + 60_000),
        },
      ],
    });
    const result = await engine.score(client, {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
      task,
      agentId: 'agent-1',
      tenantId: 'tenant-1',
    });
    // baseline 10 + agent risk flag bump 20 = 30
    expect(result.riskScore).toBe(30);
    expect(
      result.reasonCodes.some((c) =>
        c.startsWith('agent_risk_flag:prompt_injection_detected'),
      ),
    ).toBe(true);
  });

  it('an EXPIRED AgentRiskFlag contributes nothing', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService, toolRegistry);
    const client = fakeTenantClient({
      tasksById: { [task.id]: task },
      agentRiskFlags: [
        {
          agentId: 'agent-1',
          reason: 'prompt_injection_detected:edr/isolate_host',
          expiresAt: new Date(Date.now() - 1_000),
        },
      ],
    });
    const result = await engine.score(client, {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
      task,
      agentId: 'agent-1',
      tenantId: 'tenant-1',
    });
    expect(result.riskScore).toBe(10);
  });

  it('a flag on a DIFFERENT agent contributes nothing', async () => {
    const task = makeTask();
    const engine = new RiskEngine(tasksService, toolRegistry);
    const client = fakeTenantClient({
      tasksById: { [task.id]: task },
      agentRiskFlags: [
        {
          agentId: 'some-other-agent',
          reason: 'prompt_injection_detected:edr/isolate_host',
          expiresAt: new Date(Date.now() + 60_000),
        },
      ],
    });
    const result = await engine.score(client, {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
      task,
      agentId: 'agent-1',
      tenantId: 'tenant-1',
    });
    expect(result.riskScore).toBe(10);
  });

  /**
   * Phase 1 (ADR-004, CLAUDE.md §12). Three tests were removed here. Two
   * asserted `finalRiskScore = max(deterministic, advisory ?? 0)` — the
   * mechanism that let manar-ai raise a request from ALLOW to
   * APPROVAL_REQUIRED, and therefore the mechanism that put a language model
   * inside the authorization decision. A third asserted the resolved data
   * classification was forwarded to `AiAdvisoryClient.analyzeRisk`; that
   * forwarding moves to `ApprovalWorkflow`'s advisory activity, off the
   * decision path, and is tested there.
   *
   * What replaces them is the inverse assertion: the score this engine
   * produces is deterministic, full stop. The structural guarantee — that the
   * advisory client is not even reachable from the PDP's import graph — lives
   * in `src/authorization/decision-path-dependencies.spec.ts`.
   */
  it('produces a purely deterministic score, with no advisory contribution and no AI reason codes', async () => {
    const engine = new RiskEngine(tasksService, toolRegistry);
    const task = makeTask();
    const input = {
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
      task,
      agentId: 'agent-1',
      tenantId: 'tenant-1',
    };

    const first = await engine.score(
      fakeTenantClient({ tasksById: { [task.id]: task } }),
      input,
    );
    const second = await engine.score(
      fakeTenantClient({ tasksById: { [task.id]: task } }),
      input,
    );

    // Determinism: identical input, identical output. An advisory call on this
    // path would make that flaky by construction.
    expect(second).toEqual(first);
    expect(
      first.reasonCodes.some((code) => code.startsWith('ai_advisory')),
    ).toBe(false);
    expect(Object.keys(first).sort()).toEqual(['reasonCodes', 'riskScore']);
  });

  describe('data classification contributor (Phase 15a, Section 53)', () => {
    it('CONFIDENTIAL adds 10 points, recorded in reasonCodes', async () => {
      const task = makeTask();
      const engine = new RiskEngine(tasksService, toolRegistry);
      const client = fakeTenantClient({
        tasksById: { [task.id]: task },
        tools: [{ id: 'tool-1', name: 'fs' }],
        toolActions: [
          {
            toolId: 'tool-1',
            name: 'read',
            riskBaseScore: 0,
            classification: 'CONFIDENTIAL',
          },
        ],
      });
      const result = await engine.score(client, {
        toolId: 'fs',
        actionId: 'read',
        resource: 'anything',
        task,
        agentId: 'agent-1',
        tenantId: 'tenant-1',
      });
      // baseline 10 + riskBaseScore 0 + classification(CONFIDENTIAL) 10 = 20
      expect(result.riskScore).toBe(20);
      expect(result.reasonCodes).toContain(
        'tool_action_classification:CONFIDENTIAL:10',
      );
    });

    it('RESTRICTED adds 25 points, recorded in reasonCodes', async () => {
      const task = makeTask();
      const engine = new RiskEngine(tasksService, toolRegistry);
      const client = fakeTenantClient({
        tasksById: { [task.id]: task },
        tools: [{ id: 'tool-1', name: 'fs' }],
        toolActions: [
          {
            toolId: 'tool-1',
            name: 'read',
            riskBaseScore: 0,
            classification: 'RESTRICTED',
          },
        ],
      });
      const result = await engine.score(client, {
        toolId: 'fs',
        actionId: 'read',
        resource: 'anything',
        task,
        agentId: 'agent-1',
        tenantId: 'tenant-1',
      });
      // baseline 10 + riskBaseScore 0 + classification(RESTRICTED) 25 = 35
      expect(result.riskScore).toBe(35);
      expect(result.reasonCodes).toContain(
        'tool_action_classification:RESTRICTED:25',
      );
    });

    it('PUBLIC/INTERNAL contribute 0 points but are still recorded (registered ToolAction is never silently omitted)', async () => {
      const task = makeTask();
      const engine = new RiskEngine(tasksService, toolRegistry);
      const client = fakeTenantClient({
        tasksById: { [task.id]: task },
        tools: [{ id: 'tool-1', name: 'fs' }],
        toolActions: [
          {
            toolId: 'tool-1',
            name: 'read',
            riskBaseScore: 0,
            classification: 'PUBLIC',
          },
        ],
      });
      const result = await engine.score(client, {
        toolId: 'fs',
        actionId: 'read',
        resource: 'anything',
        task,
        agentId: 'agent-1',
        tenantId: 'tenant-1',
      });
      expect(result.riskScore).toBe(10);
      expect(result.reasonCodes).toContain(
        'tool_action_classification:PUBLIC:0',
      );
    });
  });
});
