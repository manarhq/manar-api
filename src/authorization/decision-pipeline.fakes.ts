import { vi } from 'vitest';
import type { AuditService } from '../audit/audit.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type {
  KillSwitchCheckResult,
  KillSwitchService,
} from '../kill-switches/kill-switch.service';
import type {
  PolicyEngine,
  PolicyEvaluationResult,
} from '../policy/policy-engine.service';
import type { RiskEngine } from '../risk/risk-engine.service';
import { TasksService, type TaskRecord } from '../tasks/tasks.service';
import { AuthorizationService } from './authorization.service';
import type { OpenFgaClientService } from './openfga-client.service';
import { allowAllCatalog } from '../platform/catalog.fakes';
import type { CatalogService } from '../platform/catalog.service';

/**
 * Test-only harness: a real `AuthorizationService` and a real `TasksService`
 * over an in-memory tenant client. `events` logs every write in order, with a
 * `:tx` suffix when it ran inside `$transaction`, so a test can assert both
 * ordering ("decision before execution") and atomicity ("increment and
 * decision in one transaction"). Excluded from the build (`tsconfig.build.json`).
 */
export interface DecisionHarnessOptions {
  task?: Partial<TaskRecord>;
  killSwitch?: KillSwitchCheckResult;
  killSwitchThrows?: boolean;
  openFgaAllowed?: boolean;
  policy?: PolicyEvaluationResult;
  riskScore?: number;
  decisionWriteFails?: boolean;
  incrementLoses?: boolean;
  grantConsumeCount?: number;
  /** Default: an unmanaged tenant (everything on). */
  catalog?: CatalogService;
}

export function makeTask(overrides: Partial<TaskRecord> = {}): TaskRecord {
  const now = Date.now();
  return {
    id: 'task-1',
    name: 'task',
    description: null,
    parentTaskId: null,
    requesterId: 'user-1',
    assignedAgentId: 'agent-1',
    status: 'ACTIVE',
    startsAt: new Date(now - 60_000),
    expiresAt: new Date(now + 3_600_000),
    maxExecutions: null,
    executionCount: 0,
    allowedToolActions: [],
    allowedResourceSelectors: [],
    forbiddenActions: [],
    riskCeiling: 50,
    createdAt: new Date(now - 60_000),
    ...overrides,
  };
}

export function makeDecisionHarness(options: DecisionHarnessOptions = {}) {
  const events: string[] = [];
  const decisions: Record<string, unknown>[] = [];
  const task = makeTask(options.task);
  let inTx = false;
  const log = (name: string) => events.push(inTx ? `${name}:tx` : name);

  const client = {
    task: {
      findUnique: vi.fn(({ where }: { where: { id: string } }) =>
        Promise.resolve(where.id === task.id ? task : null),
      ),
      update: vi.fn(() => {
        log('increment');
        task.executionCount += 1;
        return Promise.resolve(task);
      }),
      updateMany: vi.fn(() => {
        log('increment');
        if (options.incrementLoses) return Promise.resolve({ count: 0 });
        task.executionCount += 1;
        return Promise.resolve({ count: 1 });
      }),
    },
    decision: {
      create: vi.fn(({ data }: { data: Record<string, unknown> }) => {
        log('decision');
        if (options.decisionWriteFails) {
          return Promise.reject(new Error('connection terminated'));
        }
        const row = { id: `decision-${decisions.length + 1}`, ...data };
        decisions.push(row);
        return Promise.resolve(row);
      }),
    },
    authorizationGrant: {
      updateMany: vi.fn(() => {
        log('consume');
        return Promise.resolve({ count: options.grantConsumeCount ?? 1 });
      }),
    },
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => {
      inTx = true;
      try {
        return await fn(client);
      } finally {
        inTx = false;
      }
    }),
  };

  const recordSafely = vi.fn().mockResolvedValue(undefined);
  const checkAll = vi.fn(() =>
    options.killSwitchThrows
      ? Promise.reject(new Error('kill-switch store down'))
      : Promise.resolve(options.killSwitch ?? { killed: false }),
  );
  const openFgaCheck = vi.fn(() =>
    Promise.resolve(options.openFgaAllowed ?? true),
  );
  const policyEvaluate = vi.fn(() =>
    Promise.resolve(
      options.policy ?? {
        effect: 'ALLOW' as const,
        policyId: 'policy-1',
        policyVersionId: 'policy-version-1',
      },
    ),
  );
  const riskScore = vi.fn(() =>
    Promise.resolve({
      riskScore: options.riskScore ?? 10,
      reasonCodes: ['baseline'],
    }),
  );

  const service = new AuthorizationService(
    new TasksService({} as never, {} as never, {} as never),
    { check: openFgaCheck } as unknown as OpenFgaClientService,
    { evaluate: policyEvaluate } as unknown as PolicyEngine,
    { score: riskScore } as unknown as RiskEngine,
    { recordSafely } as unknown as AuditService,
    { checkAll } as unknown as KillSwitchService,
    options.catalog ?? allowAllCatalog(),
  );

  return {
    service,
    tenantClient: client as unknown as TenantPrismaClient,
    client,
    task,
    events,
    decisions,
    recordSafely,
    checkAll,
    openFgaCheck,
    policyEvaluate,
    riskScore,
  };
}
