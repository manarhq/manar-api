/* eslint-disable @typescript-eslint/require-await -- this file is an
   in-memory double for the Prisma client. Every method mirrors an async
   interface the service awaits, so the `async` is the contract being
   mocked, not an accidental promise. */
import { describe, expect, it, vi } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import {
  AiSystemInvalidTransitionError,
  AiSystemNotFoundError,
  AiSystemReferenceNotFoundError,
  AiSystemRetiredError,
  AiSystemSeparationOfDutiesError,
  AiSystemSlugConflictError,
} from './ai-systems.errors';
import {
  AiSystemsService,
  ALLOWED_TRANSITIONS,
  type AiSystemLifecycleState,
} from './ai-systems.service';

/**
 * Release 2026-11-11 (brief §3.1). Hand-rolled in-memory fakes, no real
 * database and no Nest DI container — the same style
 * `credential-broker.service.spec.ts` and `risk-engine.service.spec.ts`
 * already use in this repo.
 *
 * What these tests are actually for: the three invariants named in
 * `AiSystemsService`'s doc comment. Each one is a rule an operator would
 * be entitled to rely on when this record is used as governance evidence,
 * and each is expressed here as "the wrong thing is rejected", not as
 * "the happy path returns 200".
 */

interface FakeRow {
  [key: string]: unknown;
}

/**
 * A deliberately small fake: only the model delegates `AiSystemsService`
 * touches, backed by plain arrays. `$transaction(fn)` runs the callback
 * against the same store, which is exactly the semantic the service relies
 * on (its transactional guarantee is that the version row and the update
 * commit together — the fake preserves the *ordering*, and the real
 * guarantee is Postgres's job, verified at the e2e level).
 */
function makeTenantClient(seed: {
  aiSystems?: FakeRow[];
  agents?: FakeRow[];
  tools?: FakeRow[];
  users?: FakeRow[];
  transitions?: FakeRow[];
  agentLinks?: FakeRow[];
  toolLinks?: FakeRow[];
  toolInvocationGroupBy?: () => Promise<unknown[]>;
}) {
  const store = {
    aiSystems: seed.aiSystems ?? [],
    aiSystemVersions: [] as FakeRow[],
    transitions: seed.transitions ?? [],
    agentLinks: seed.agentLinks ?? [],
    toolLinks: seed.toolLinks ?? [],
    agents: seed.agents ?? [],
    tools: seed.tools ?? [],
    users: seed.users ?? [{ id: 'user-owner' }],
  };

  const findIn = (rows: FakeRow[], where: Record<string, unknown>) =>
    rows.find((row) =>
      Object.entries(where).every(([key, value]) => row[key] === value),
    ) ?? null;

  const client = {
    aiSystem: {
      findUnique: vi.fn(async ({ where }: { where: Record<string, unknown> }) =>
        findIn(store.aiSystems, where),
      ),
      findMany: vi.fn(async () => store.aiSystems),
      create: vi.fn(async ({ data }: { data: FakeRow }) => {
        const row = {
          id: `ai-system-${store.aiSystems.length + 1}`,
          lifecycleState: 'DRAFT',
          dataClassification: 'INTERNAL',
          version: 1,
          createdAt: new Date('2026-09-08T10:00:00.000Z'),
          updatedAt: new Date('2026-09-08T10:00:00.000Z'),
          nextReviewDate: null,
          declaredProvider: null,
          declaredModel: null,
          ...data,
        };
        store.aiSystems.push(row);
        return row;
      }),
      update: vi.fn(
        async ({
          where,
          data,
        }: {
          where: { id: string };
          data: Record<string, unknown>;
        }) => {
          const row = findIn(store.aiSystems, where);
          if (row === null) throw new Error('fake: no such AiSystem');
          for (const [key, value] of Object.entries(data)) {
            if (
              typeof value === 'object' &&
              value !== null &&
              'increment' in (value as Record<string, unknown>)
            ) {
              row[key] =
                (row[key] as number) +
                ((value as { increment: number }).increment ?? 0);
            } else {
              row[key] = value;
            }
          }
          return row;
        },
      ),
    },
    aiSystemVersion: {
      create: vi.fn(async ({ data }: { data: FakeRow }) => {
        store.aiSystemVersions.push(data);
        return data;
      }),
      findMany: vi.fn(async () => store.aiSystemVersions),
    },
    aiSystemStateTransition: {
      create: vi.fn(async ({ data }: { data: FakeRow }) => {
        store.transitions.push({ ...data, at: new Date() });
        return data;
      }),
      findFirst: vi.fn(
        async ({ where }: { where: Record<string, unknown> }) =>
          [...store.transitions]
            .reverse()
            .find((row) =>
              Object.entries(where).every(([key, value]) => row[key] === value),
            ) ?? null,
      ),
      findMany: vi.fn(async () => store.transitions),
    },
    aiSystemAgentLink: {
      findMany: vi.fn(async () => store.agentLinks),
      findUnique: vi.fn(
        async ({
          where,
        }: {
          where: {
            aiSystemId_agentId: { aiSystemId: string; agentId: string };
          };
        }) =>
          findIn(store.agentLinks, {
            aiSystemId: where.aiSystemId_agentId.aiSystemId,
            agentId: where.aiSystemId_agentId.agentId,
          }),
      ),
      create: vi.fn(async ({ data }: { data: FakeRow }) => {
        store.agentLinks.push(data);
        return data;
      }),
      deleteMany: vi.fn(
        async ({ where }: { where: Record<string, unknown> }) => {
          const before = store.agentLinks.length;
          store.agentLinks = store.agentLinks.filter(
            (row) =>
              !Object.entries(where).every(
                ([key, value]) => row[key] === value,
              ),
          );
          return { count: before - store.agentLinks.length };
        },
      ),
    },
    aiSystemToolLink: {
      findMany: vi.fn(async () => store.toolLinks),
      findUnique: vi.fn(async () => null),
      create: vi.fn(async ({ data }: { data: FakeRow }) => {
        store.toolLinks.push(data);
        return data;
      }),
      deleteMany: vi.fn(async () => ({ count: 0 })),
    },
    agent: {
      findUnique: vi.fn(async ({ where }: { where: Record<string, unknown> }) =>
        findIn(store.agents, where),
      ),
    },
    tool: {
      findUnique: vi.fn(async ({ where }: { where: Record<string, unknown> }) =>
        findIn(store.tools, where),
      ),
    },
    userProfile: {
      findUnique: vi.fn(async ({ where }: { where: Record<string, unknown> }) =>
        findIn(store.users, where),
      ),
    },
    toolInvocation: {
      groupBy: vi.fn(
        seed.toolInvocationGroupBy ?? (async () => [] as unknown[]),
      ),
    },
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) =>
      fn(client),
    ),
  };

  return { client: client as unknown as TenantPrismaClient, store };
}

function makeAuditService() {
  const recorded: { eventType: string; data: unknown; actor: unknown }[] = [];
  const auditService = {
    recordSafely: vi.fn(
      async (
        _client: unknown,
        _tenantId: string,
        event: { eventType: string; data: unknown; actor: unknown },
      ) => {
        recorded.push(event);
      },
    ),
  } as unknown as AuditService;
  return { auditService, recorded };
}

function aiSystemRow(overrides: FakeRow = {}): FakeRow {
  return {
    id: 'ai-1',
    slug: 'claims-triage',
    name: 'Claims triage assistant',
    businessPurpose: 'Triages inbound claims',
    ownerId: 'user-owner',
    businessUnit: 'Claims Operations',
    environment: 'PRODUCTION',
    lifecycleState: 'DRAFT',
    dataClassification: 'CONFIDENTIAL',
    declaredProvider: 'ollama',
    declaredModel: 'qwen3',
    riskRationale: 'Handles customer PII under human review.',
    nextReviewDate: null,
    version: 1,
    createdAt: new Date('2026-09-01T00:00:00.000Z'),
    createdBy: 'user-creator',
    updatedAt: new Date('2026-09-01T00:00:00.000Z'),
    ...overrides,
  };
}

describe('AiSystemsService — creation', () => {
  it('always creates in DRAFT, whatever the caller sends', async () => {
    const { client, store } = makeTenantClient({});
    const { auditService, recorded } = makeAuditService();
    const service = new AiSystemsService(auditService);

    const created = await service.createAiSystem(client, {
      slug: 'claims-triage',
      name: 'Claims triage assistant',
      businessPurpose: 'Triages inbound claims',
      ownerId: 'user-owner',
      businessUnit: 'Claims Operations',
      environment: 'PRODUCTION',
      riskRationale: 'Handles customer PII under human review.',
      tenantId: 'tenant-1',
      createdByUserId: 'user-creator',
    });

    expect(created.lifecycleState).toBe('DRAFT');
    expect(store.aiSystems).toHaveLength(1);
    expect(recorded[0]?.eventType).toBe(AUDIT_EVENT_TYPES.AI_SYSTEM_CREATED);
  });

  it('rejects an owner that does not exist in this tenant, before writing anything', async () => {
    const { client, store } = makeTenantClient({ users: [] });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    await expect(
      service.createAiSystem(client, {
        slug: 'claims-triage',
        name: 'n',
        businessPurpose: 'p',
        ownerId: 'ghost-user',
        businessUnit: 'b',
        environment: 'PRODUCTION',
        riskRationale: 'r',
        tenantId: 'tenant-1',
        createdByUserId: 'user-creator',
      }),
    ).rejects.toBeInstanceOf(AiSystemReferenceNotFoundError);

    expect(store.aiSystems).toHaveLength(0);
  });

  it('rejects a duplicate slug', async () => {
    const { client } = makeTenantClient({ aiSystems: [aiSystemRow()] });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    await expect(
      service.createAiSystem(client, {
        slug: 'claims-triage',
        name: 'n',
        businessPurpose: 'p',
        ownerId: 'user-owner',
        businessUnit: 'b',
        environment: 'STAGING',
        riskRationale: 'r',
        tenantId: 'tenant-1',
        createdByUserId: 'user-creator',
      }),
    ).rejects.toBeInstanceOf(AiSystemSlugConflictError);
  });
});

describe('AiSystemsService — lifecycle transitions', () => {
  /**
   * The edge table is the security control, so it is asserted exhaustively
   * rather than by sampling: every (from, to) pair either appears in
   * ALLOWED_TRANSITIONS or must be rejected.
   */
  const ALL_STATES: AiSystemLifecycleState[] = [
    'DRAFT',
    'REVIEW',
    'ACTIVE',
    'SUSPENDED',
    'RETIRED',
  ];

  it.each(ALL_STATES)(
    'rejects every transition out of %s that is not in the allowed-edge table',
    async (fromState) => {
      const disallowed = ALL_STATES.filter(
        (toState) => !ALLOWED_TRANSITIONS[fromState].includes(toState),
      );

      for (const toState of disallowed) {
        const { client, store } = makeTenantClient({
          aiSystems: [aiSystemRow({ lifecycleState: fromState })],
        });
        const { auditService } = makeAuditService();
        const service = new AiSystemsService(auditService);

        await expect(
          service.transitionState(client, {
            toState,
            reason: 'attempted',
            tenantId: 'tenant-1',
            aiSystemId: 'ai-1',
            actorUserId: 'user-a',
          }),
        ).rejects.toBeInstanceOf(AiSystemInvalidTransitionError);

        // And crucially: no state change and no history row was written.
        expect(store.aiSystems[0]?.lifecycleState).toBe(fromState);
        expect(store.transitions).toHaveLength(0);
      }
    },
  );

  it('records a transition row and an audit event on an allowed edge', async () => {
    const { client, store } = makeTenantClient({
      aiSystems: [aiSystemRow({ lifecycleState: 'DRAFT' })],
    });
    const { auditService, recorded } = makeAuditService();
    const service = new AiSystemsService(auditService);

    const updated = await service.transitionState(client, {
      toState: 'REVIEW',
      reason: 'Ready for governance review',
      tenantId: 'tenant-1',
      aiSystemId: 'ai-1',
      actorUserId: 'user-submitter',
    });

    expect(updated.lifecycleState).toBe('REVIEW');
    expect(store.transitions).toHaveLength(1);
    expect(store.transitions[0]).toMatchObject({
      fromState: 'DRAFT',
      toState: 'REVIEW',
      reason: 'Ready for governance review',
      actorId: 'user-submitter',
    });
    expect(recorded[0]?.eventType).toBe(
      AUDIT_EVENT_TYPES.AI_SYSTEM_STATE_CHANGED,
    );
  });

  it('blocks REVIEW -> ACTIVE by the same user who submitted for review', async () => {
    // The failure this prevents: one person walking a record
    // DRAFT -> REVIEW -> ACTIVE alone, which would make the review state
    // decorative.
    const { client, store } = makeTenantClient({
      aiSystems: [aiSystemRow({ lifecycleState: 'REVIEW' })],
      transitions: [
        {
          aiSystemId: 'ai-1',
          fromState: 'DRAFT',
          toState: 'REVIEW',
          actorId: 'user-submitter',
          reason: 'submitted',
          at: new Date('2026-09-02T00:00:00.000Z'),
        },
      ],
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    await expect(
      service.transitionState(client, {
        toState: 'ACTIVE',
        reason: 'self-approving',
        tenantId: 'tenant-1',
        aiSystemId: 'ai-1',
        actorUserId: 'user-submitter',
      }),
    ).rejects.toBeInstanceOf(AiSystemSeparationOfDutiesError);

    expect(store.aiSystems[0]?.lifecycleState).toBe('REVIEW');
  });

  it('allows REVIEW -> ACTIVE by a different user', async () => {
    const { client, store } = makeTenantClient({
      aiSystems: [aiSystemRow({ lifecycleState: 'REVIEW' })],
      transitions: [
        {
          aiSystemId: 'ai-1',
          fromState: 'DRAFT',
          toState: 'REVIEW',
          actorId: 'user-submitter',
          reason: 'submitted',
          at: new Date('2026-09-02T00:00:00.000Z'),
        },
      ],
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    const updated = await service.transitionState(client, {
      toState: 'ACTIVE',
      reason: 'Reviewed, controls confirmed',
      tenantId: 'tenant-1',
      aiSystemId: 'ai-1',
      actorUserId: 'user-reviewer',
    });

    expect(updated.lifecycleState).toBe('ACTIVE');
    expect(store.aiSystems[0]?.lifecycleState).toBe('ACTIVE');
  });

  it('compares against the most recent submission, so a reworked record is re-checked', async () => {
    // A record submitted by A, sent back, then resubmitted by B must be
    // activatable by A — the rule is about the *current* submission.
    const { client } = makeTenantClient({
      aiSystems: [aiSystemRow({ lifecycleState: 'REVIEW' })],
      transitions: [
        {
          aiSystemId: 'ai-1',
          fromState: 'DRAFT',
          toState: 'REVIEW',
          actorId: 'user-a',
          reason: 'first submission',
          at: new Date('2026-09-02T00:00:00.000Z'),
        },
        {
          aiSystemId: 'ai-1',
          fromState: 'REVIEW',
          toState: 'DRAFT',
          actorId: 'user-b',
          reason: 'rework',
          at: new Date('2026-09-03T00:00:00.000Z'),
        },
        {
          aiSystemId: 'ai-1',
          fromState: 'DRAFT',
          toState: 'REVIEW',
          actorId: 'user-b',
          reason: 'resubmitted',
          at: new Date('2026-09-04T00:00:00.000Z'),
        },
      ],
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    const updated = await service.transitionState(client, {
      toState: 'ACTIVE',
      reason: 'Reviewed',
      tenantId: 'tenant-1',
      aiSystemId: 'ai-1',
      actorUserId: 'user-a',
    });

    expect(updated.lifecycleState).toBe('ACTIVE');
  });

  it('reports an invalid edge as an invalid edge even when the caller would also fail separation of duties', async () => {
    const { client } = makeTenantClient({
      aiSystems: [aiSystemRow({ lifecycleState: 'ACTIVE' })],
      transitions: [
        {
          aiSystemId: 'ai-1',
          fromState: 'DRAFT',
          toState: 'REVIEW',
          actorId: 'user-a',
          reason: 'submitted',
          at: new Date(),
        },
      ],
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    await expect(
      service.transitionState(client, {
        toState: 'DRAFT',
        reason: 'back to draft',
        tenantId: 'tenant-1',
        aiSystemId: 'ai-1',
        actorUserId: 'user-a',
      }),
    ).rejects.toBeInstanceOf(AiSystemInvalidTransitionError);
  });
});

describe('AiSystemsService — material change versioning', () => {
  it('snapshots the prior governed fields and increments version', async () => {
    const { client, store } = makeTenantClient({
      aiSystems: [aiSystemRow({ lifecycleState: 'ACTIVE' })],
    });
    const { auditService, recorded } = makeAuditService();
    const service = new AiSystemsService(auditService);

    const updated = await service.updateAiSystem(client, {
      declaredModel: 'qwen3-32b',
      changeReason: 'Upgraded the model after the Q3 review',
      tenantId: 'tenant-1',
      aiSystemId: 'ai-1',
      actorUserId: 'user-manager',
    });

    expect(updated.version).toBe(2);
    expect(updated.declaredModel).toBe('qwen3-32b');

    expect(store.aiSystemVersions).toHaveLength(1);
    const snapshot = store.aiSystemVersions[0] as {
      version: number;
      snapshot: Record<string, unknown>;
      changeReason: string;
      changedBy: string;
    };
    expect(snapshot.version).toBe(1);
    // The snapshot holds the state *before* the change — this is what makes
    // "what did this record say last month" answerable.
    expect(snapshot.snapshot.declaredModel).toBe('qwen3');
    expect(snapshot.changeReason).toBe(
      'Upgraded the model after the Q3 review',
    );
    expect(snapshot.changedBy).toBe('user-manager');

    expect(recorded[0]?.eventType).toBe(AUDIT_EVENT_TYPES.AI_SYSTEM_UPDATED);
  });

  it('refuses to modify a RETIRED system', async () => {
    const { client, store } = makeTenantClient({
      aiSystems: [aiSystemRow({ lifecycleState: 'RETIRED' })],
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    await expect(
      service.updateAiSystem(client, {
        name: 'renamed',
        changeReason: 'tidy up',
        tenantId: 'tenant-1',
        aiSystemId: 'ai-1',
        actorUserId: 'user-manager',
      }),
    ).rejects.toBeInstanceOf(AiSystemRetiredError);

    expect(store.aiSystemVersions).toHaveLength(0);
  });

  it('throws AiSystemNotFoundError rather than creating anything for an unknown id', async () => {
    const { client } = makeTenantClient({ aiSystems: [] });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    await expect(
      service.updateAiSystem(client, {
        name: 'x',
        changeReason: 'y',
        tenantId: 'tenant-1',
        aiSystemId: 'missing',
        actorUserId: 'user-manager',
      }),
    ).rejects.toBeInstanceOf(AiSystemNotFoundError);
  });
});

describe('AiSystemsService — derived coverage', () => {
  it('reports MONITORING_UNAVAILABLE when the observation query fails, not DECLARED_ONLY', async () => {
    // This is the degradation path the brief specifically calls out:
    // silence must not read as good health.
    const { client } = makeTenantClient({
      aiSystems: [aiSystemRow()],
      agents: [{ id: 'agent-1', status: 'ACTIVE' }],
      agentLinks: [
        {
          aiSystemId: 'ai-1',
          agentId: 'agent-1',
          linkedBy: 'user-manager',
          linkedAt: new Date('2026-09-02T00:00:00.000Z'),
          agent: {
            id: 'agent-1',
            slug: 'triage-bot',
            displayName: 'Triage bot',
            status: 'ACTIVE',
          },
        },
      ],
      toolInvocationGroupBy: async () => {
        throw new Error('connection terminated');
      },
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    const detail = await service.getAiSystemOrThrow(client, 'ai-1');

    expect(detail.coverage.coverage).toBe('MONITORING_UNAVAILABLE');
    // The declared facts survive; only the observation figures are withheld.
    expect(detail.coverage.linkedAgentCount).toBe(1);
    expect(detail.coverage.activeLinkedAgentCount).toBe(1);
    expect(detail.coverage.lastObservedAt).toBeNull();
  });

  it('does not consult the telemetry source at all when nothing is linked, and calls that a real answer', async () => {
    const groupBy = vi.fn(async () => []);
    const { client } = makeTenantClient({
      aiSystems: [aiSystemRow()],
      toolInvocationGroupBy: groupBy,
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    const detail = await service.getAiSystemOrThrow(client, 'ai-1');

    expect(groupBy).not.toHaveBeenCalled();
    expect(detail.coverage.coverage).toBe('DECLARED_ONLY');
  });
});

describe('AiSystemsService — agent links', () => {
  it('is a no-op rather than an error when the agent is already linked', async () => {
    const { client, store } = makeTenantClient({
      aiSystems: [aiSystemRow()],
      agents: [{ id: 'agent-1', status: 'ACTIVE' }],
      agentLinks: [{ aiSystemId: 'ai-1', agentId: 'agent-1' }],
    });
    const { auditService, recorded } = makeAuditService();
    const service = new AiSystemsService(auditService);

    const result = await service.linkAgent(client, {
      tenantId: 'tenant-1',
      aiSystemId: 'ai-1',
      agentId: 'agent-1',
      actorUserId: 'user-manager',
    });

    expect(result).toEqual({ linked: false });
    expect(store.agentLinks).toHaveLength(1);
    // No duplicate audit noise for a retried request.
    expect(recorded).toHaveLength(0);
  });

  it('rejects linking an agent that does not exist in this tenant', async () => {
    const { client } = makeTenantClient({
      aiSystems: [aiSystemRow()],
      agents: [],
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    await expect(
      service.linkAgent(client, {
        tenantId: 'tenant-1',
        aiSystemId: 'ai-1',
        agentId: 'ghost-agent',
        actorUserId: 'user-manager',
      }),
    ).rejects.toBeInstanceOf(AiSystemReferenceNotFoundError);
  });

  it('refuses to link anything to a RETIRED system', async () => {
    const { client } = makeTenantClient({
      aiSystems: [aiSystemRow({ lifecycleState: 'RETIRED' })],
      agents: [{ id: 'agent-1', status: 'ACTIVE' }],
    });
    const { auditService } = makeAuditService();
    const service = new AiSystemsService(auditService);

    await expect(
      service.linkAgent(client, {
        tenantId: 'tenant-1',
        aiSystemId: 'ai-1',
        agentId: 'agent-1',
        actorUserId: 'user-manager',
      }),
    ).rejects.toBeInstanceOf(AiSystemRetiredError);
  });
});
