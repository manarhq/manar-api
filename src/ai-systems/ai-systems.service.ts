import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  CursorPage,
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import {
  DEFAULT_OBSERVATION_WINDOW_DAYS,
  deriveCoverage,
  type CoverageResult,
  type LinkedAgentObservation,
} from './ai-system-coverage';
import {
  AiSystemInvalidTransitionError,
  AiSystemNotFoundError,
  AiSystemReferenceNotFoundError,
  AiSystemRetiredError,
  AiSystemSeparationOfDutiesError,
  AiSystemSlugConflictError,
} from './ai-systems.errors';
import type {
  CreateAiSystemRequest,
  TransitionAiSystemRequest,
  UpdateAiSystemRequest,
} from './ai-systems.validation';

export type AiSystemLifecycleState =
  'DRAFT' | 'REVIEW' | 'ACTIVE' | 'SUSPENDED' | 'RETIRED';
export type AiSystemEnvironment = 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION';
export type DataClassification =
  'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

/**
 * The server-enforced lifecycle graph (brief §3.1: "server-enforced
 * transition rules"). Edges, and the reasoning behind the ones that are
 * *absent*:
 *
 * - `DRAFT -> REVIEW` — submit for review. `DRAFT -> ACTIVE` is
 *   deliberately not an edge: activating without review is precisely the
 *   control this state machine exists to impose.
 * - `REVIEW -> ACTIVE` — the reviewed activation. Subject to the
 *   separation-of-duties check in `transitionState`.
 * - `REVIEW -> DRAFT` — send back for rework.
 * - `ACTIVE <-> SUSPENDED` — temporary governance hold and its release.
 * - anything (except `RETIRED`) `-> RETIRED` — terminal.
 *
 * `RETIRED` has no outgoing edges. Un-retiring would make a retired
 * system's evidence trail ambiguous ("was this in service on 4 October?"
 * would depend on replaying transitions rather than reading a state), so
 * the supported path is to create a new system and cite the retired one.
 */
export const ALLOWED_TRANSITIONS: Readonly<
  Record<AiSystemLifecycleState, readonly AiSystemLifecycleState[]>
> = {
  DRAFT: ['REVIEW', 'RETIRED'],
  REVIEW: ['ACTIVE', 'DRAFT', 'RETIRED'],
  ACTIVE: ['SUSPENDED', 'RETIRED'],
  SUSPENDED: ['ACTIVE', 'RETIRED'],
  RETIRED: [],
};

/**
 * Transitions that may not be performed by the same human who performed
 * the transition that put the system into its current state.
 *
 * Only `REVIEW -> ACTIVE` qualifies. The point of the review state is that
 * somebody other than the submitter agreed; letting one person move a
 * record `DRAFT -> REVIEW -> ACTIVE` unaided would make the review state
 * decorative. The other edges are deliberately *not* covered: an operator
 * suspending a system they activated is a legitimate, urgent action, and
 * requiring a second person there would create pressure to skip the
 * governance record entirely.
 */
const SEPARATION_OF_DUTIES_EDGES: ReadonlySet<string> = new Set([
  'REVIEW->ACTIVE',
]);

/** The governed field set — the exact keys snapshotted into `AiSystemVersion.snapshot`. */
// A type alias, not an interface: the governed field set is persisted
// verbatim into AiSystemVersion.snapshot (a Prisma Json column), and only
// type aliases carry the implicit index signature Prisma's InputJsonObject
// requires.
export type AiSystemGovernedFields = {
  slug: string;
  name: string;
  businessPurpose: string;
  ownerId: string;
  businessUnit: string;
  environment: AiSystemEnvironment;
  dataClassification: DataClassification;
  declaredProvider: string | null;
  declaredModel: string | null;
  riskRationale: string;
  nextReviewDate: string | null;
  lifecycleState: AiSystemLifecycleState;
};

export interface AiSystemSummary extends AiSystemGovernedFields {
  id: string;
  version: number;
  createdAt: Date;
  createdBy: string;
  updatedAt: Date;
}

/**
 * A summary plus everything derived. `coverage` is computed per request
 * from live observations and is never read from a column — see
 * `ai-system-coverage.ts` for why.
 */
export interface AiSystemDetail extends AiSystemSummary {
  coverage: CoverageResult;
  linkedAgents: {
    agentId: string;
    slug: string;
    displayName: string;
    status: string;
    linkedAt: Date;
    linkedBy: string;
    lastObservedAt: Date | null;
  }[];
  linkedTools: {
    toolId: string;
    name: string;
    linkedAt: Date;
    linkedBy: string;
  }[];
}

export interface ListAiSystemsInput {
  lifecycleState?: AiSystemLifecycleState;
  environment?: AiSystemEnvironment;
  ownerId?: string;
  limit: number;
  cursor?: DecodedCursor;
}

export interface CreateAiSystemInput extends CreateAiSystemRequest {
  tenantId: string;
  createdByUserId: string;
}

export interface UpdateAiSystemInput extends UpdateAiSystemRequest {
  tenantId: string;
  aiSystemId: string;
  actorUserId: string;
}

export interface TransitionAiSystemInput extends TransitionAiSystemRequest {
  tenantId: string;
  aiSystemId: string;
  actorUserId: string;
}

type AiSystemRow = {
  id: string;
  slug: string;
  name: string;
  businessPurpose: string;
  ownerId: string;
  businessUnit: string;
  environment: string;
  lifecycleState: string;
  dataClassification: string;
  declaredProvider: string | null;
  declaredModel: string | null;
  riskRationale: string;
  nextReviewDate: Date | null;
  version: number;
  createdAt: Date;
  createdBy: string;
  updatedAt: Date;
};

function toSummary(row: AiSystemRow): AiSystemSummary {
  return {
    id: row.id,
    slug: row.slug,
    name: row.name,
    businessPurpose: row.businessPurpose,
    ownerId: row.ownerId,
    businessUnit: row.businessUnit,
    environment: row.environment as AiSystemEnvironment,
    lifecycleState: row.lifecycleState as AiSystemLifecycleState,
    dataClassification: row.dataClassification as DataClassification,
    declaredProvider: row.declaredProvider,
    declaredModel: row.declaredModel,
    riskRationale: row.riskRationale,
    nextReviewDate: row.nextReviewDate?.toISOString() ?? null,
    version: row.version,
    createdAt: row.createdAt,
    createdBy: row.createdBy,
    updatedAt: row.updatedAt,
  };
}

/** The snapshot written into `AiSystemVersion.snapshot` — governed fields only, no ids/timestamps that would make two snapshots differ for uninteresting reasons. */
function toGovernedFields(row: AiSystemRow): AiSystemGovernedFields {
  const summary = toSummary(row);
  return {
    slug: summary.slug,
    name: summary.name,
    businessPurpose: summary.businessPurpose,
    ownerId: summary.ownerId,
    businessUnit: summary.businessUnit,
    environment: summary.environment,
    dataClassification: summary.dataClassification,
    declaredProvider: summary.declaredProvider,
    declaredModel: summary.declaredModel,
    riskRationale: summary.riskRationale,
    nextReviewDate: summary.nextReviewDate,
    lifecycleState: summary.lifecycleState,
  };
}

/**
 * Release 2026-11-11 (brief §3.1) — the AI-system/use-case inventory.
 *
 * This is the record that turns an agent-enforcement runtime into a
 * governance platform: it names the *business* system an accountable owner
 * is answerable for, and gives findings, investigations, assessments, and
 * evidence something durable to attach to.
 *
 * Three invariants this service enforces and that its tests pin:
 *
 * 1. **Declared ≠ verified.** `coverage` is derived per read from real
 *    `ToolInvocation` rows and `Agent.status`; there is no stored coverage
 *    column to go stale (see `ai-system-coverage.ts`).
 * 2. **Lifecycle moves only through `transitionState`.** `PATCH` cannot
 *    change `lifecycleState`, so the allowed-edge table and the
 *    separation-of-duties rule have no bypass.
 * 3. **Material change is versioned before it is applied.** The prior
 *    governed field set is snapshotted into `AiSystemVersion` inside the
 *    same transaction as the update, so history can never be missing for a
 *    change that took effect.
 */
@Injectable()
export class AiSystemsService {
  private readonly logger = new Logger(AiSystemsService.name);

  constructor(private readonly auditService: AuditService) {}

  /**
   * `POST /ai-systems`. Always lands in `DRAFT` — the caller cannot choose
   * a starting state, because every other state is supposed to be the
   * result of a recorded transition rather than of how the record happened
   * to be created.
   */
  async createAiSystem(
    tenantClient: TenantPrismaClient,
    input: CreateAiSystemInput,
  ): Promise<AiSystemSummary> {
    await this.assertUserExists(tenantClient, input.ownerId);

    const existing = await tenantClient.aiSystem.findUnique({
      where: { slug: input.slug },
      select: { id: true },
    });
    if (existing !== null) {
      throw new AiSystemSlugConflictError(input.slug);
    }

    const row = await tenantClient.aiSystem.create({
      data: {
        slug: input.slug,
        name: input.name,
        businessPurpose: input.businessPurpose,
        ownerId: input.ownerId,
        businessUnit: input.businessUnit,
        environment: input.environment,
        dataClassification: input.dataClassification ?? 'INTERNAL',
        declaredProvider: input.declaredProvider ?? null,
        declaredModel: input.declaredModel ?? null,
        riskRationale: input.riskRationale,
        nextReviewDate: input.nextReviewDate ?? null,
        createdBy: input.createdByUserId,
      },
    });

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SYSTEM_CREATED,
      actor: { type: 'human', id: input.createdByUserId },
      data: {
        aiSystemId: row.id,
        slug: row.slug,
        ownerId: row.ownerId,
        environment: row.environment,
        dataClassification: row.dataClassification,
        lifecycleState: row.lifecycleState,
      },
    });

    return toSummary(row);
  }

  /** `GET /ai-systems` — cursor-paginated, newest first. */
  async listAiSystems(
    tenantClient: TenantPrismaClient,
    input: ListAiSystemsInput,
  ): Promise<CursorPage<AiSystemSummary>> {
    const where = {
      ...(input.lifecycleState !== undefined
        ? { lifecycleState: input.lifecycleState }
        : {}),
      ...(input.environment !== undefined
        ? { environment: input.environment }
        : {}),
      ...(input.ownerId !== undefined ? { ownerId: input.ownerId } : {}),
      ...cursorWhereClause('createdAt', input.cursor),
    };
    const rows = await tenantClient.aiSystem.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
    });
    const page = toCursorPage(rows, input.limit, (row) => row.createdAt);
    return {
      items: page.items.map(toSummary),
      nextCursor: page.nextCursor,
    };
  }

  /**
   * `GET /ai-systems/:id` — the full record including derived coverage and
   * both link sets.
   *
   * Coverage derivation is wrapped so that a failure of the observation
   * query degrades to `MONITORING_UNAVAILABLE` rather than failing the
   * whole read: an operator who cannot see the record at all during a
   * partial outage is worse off than one who can see it marked "monitoring
   * unavailable", and the brief requires those two states to be
   * distinguishable anyway.
   */
  async getAiSystemOrThrow(
    tenantClient: TenantPrismaClient,
    aiSystemId: string,
    options?: { observationWindowDays?: number; now?: Date },
  ): Promise<AiSystemDetail> {
    const row = await tenantClient.aiSystem.findUnique({
      where: { id: aiSystemId },
    });
    if (row === null) {
      throw new AiSystemNotFoundError(aiSystemId);
    }

    const agentLinks = await tenantClient.aiSystemAgentLink.findMany({
      where: { aiSystemId },
      include: {
        agent: {
          select: {
            id: true,
            slug: true,
            displayName: true,
            status: true,
          },
        },
      },
      orderBy: { linkedAt: 'asc' },
    });

    const toolLinks = await tenantClient.aiSystemToolLink.findMany({
      where: { aiSystemId },
      include: { tool: { select: { id: true, name: true } } },
      orderBy: { linkedAt: 'asc' },
    });

    const observationWindowDays =
      options?.observationWindowDays ?? DEFAULT_OBSERVATION_WINDOW_DAYS;
    const now = options?.now ?? new Date();

    const { observations, telemetryAvailable } = await this.loadObservations(
      tenantClient,
      agentLinks.map((link) => link.agentId),
    );

    const linkedAgentObservations: LinkedAgentObservation[] = agentLinks.map(
      (link) => ({
        agentId: link.agentId,
        status: link.agent.status,
        lastObservedAt: observations.get(link.agentId) ?? null,
      }),
    );

    const coverage = deriveCoverage({
      telemetryAvailable,
      linkedAgents: linkedAgentObservations,
      observationWindowDays,
      now,
    });

    return {
      ...toSummary(row),
      coverage,
      linkedAgents: agentLinks.map((link) => ({
        agentId: link.agentId,
        slug: link.agent.slug,
        displayName: link.agent.displayName,
        status: link.agent.status,
        linkedAt: link.linkedAt,
        linkedBy: link.linkedBy,
        lastObservedAt: observations.get(link.agentId) ?? null,
      })),
      linkedTools: toolLinks.map((link) => ({
        toolId: link.toolId,
        name: link.tool.name,
        linkedAt: link.linkedAt,
        linkedBy: link.linkedBy,
      })),
    };
  }

  /**
   * Most-recent `ToolInvocation.startedAt` per agent.
   *
   * Returns `telemetryAvailable: false` on a query failure rather than
   * letting the error propagate or — far worse — returning an empty map,
   * which `deriveCoverage` would otherwise read as "this system has never
   * run". Distinguishing "no evidence" from "could not look" is the whole
   * point of the fourth coverage value.
   */
  private async loadObservations(
    tenantClient: TenantPrismaClient,
    agentIds: string[],
  ): Promise<{ observations: Map<string, Date>; telemetryAvailable: boolean }> {
    if (agentIds.length === 0) {
      // Nothing to look up. This is a genuine, complete answer — the
      // telemetry source was not needed, not unavailable.
      return { observations: new Map(), telemetryAvailable: true };
    }

    try {
      const grouped = await tenantClient.toolInvocation.groupBy({
        by: ['agentId'],
        where: { agentId: { in: agentIds } },
        _max: { startedAt: true },
      });
      const observations = new Map<string, Date>();
      for (const entry of grouped) {
        if (entry._max.startedAt !== null) {
          observations.set(entry.agentId, entry._max.startedAt);
        }
      }
      return { observations, telemetryAvailable: true };
    } catch (error) {
      this.logger.error(
        `Coverage observation query failed; reporting MONITORING_UNAVAILABLE rather than assuming no activity: ${String(error)}`,
      );
      return { observations: new Map(), telemetryAvailable: false };
    }
  }

  /**
   * `PATCH /ai-systems/:id`. Snapshots the pre-change governed fields into
   * `AiSystemVersion` and increments `version`, both inside one
   * transaction with the update itself — so there is no interleaving in
   * which a change is applied without its history row.
   */
  async updateAiSystem(
    tenantClient: TenantPrismaClient,
    input: UpdateAiSystemInput,
  ): Promise<AiSystemSummary> {
    const current = await tenantClient.aiSystem.findUnique({
      where: { id: input.aiSystemId },
    });
    if (current === null) {
      throw new AiSystemNotFoundError(input.aiSystemId);
    }
    if (current.lifecycleState === 'RETIRED') {
      throw new AiSystemRetiredError(input.aiSystemId);
    }
    if (input.ownerId !== undefined) {
      await this.assertUserExists(tenantClient, input.ownerId);
    }

    const priorSnapshot = toGovernedFields(current);

    const data: Record<string, unknown> = {};
    if (input.name !== undefined) data.name = input.name;
    if (input.businessPurpose !== undefined)
      data.businessPurpose = input.businessPurpose;
    if (input.ownerId !== undefined) data.ownerId = input.ownerId;
    if (input.businessUnit !== undefined)
      data.businessUnit = input.businessUnit;
    if (input.environment !== undefined) data.environment = input.environment;
    if (input.dataClassification !== undefined)
      data.dataClassification = input.dataClassification;
    if (input.declaredProvider !== undefined)
      data.declaredProvider = input.declaredProvider;
    if (input.declaredModel !== undefined)
      data.declaredModel = input.declaredModel;
    if (input.riskRationale !== undefined)
      data.riskRationale = input.riskRationale;
    if (input.nextReviewDate !== undefined)
      data.nextReviewDate = input.nextReviewDate;

    const updated = await tenantClient.$transaction(async (tx) => {
      await tx.aiSystemVersion.create({
        data: {
          aiSystemId: current.id,
          version: current.version,
          snapshot: priorSnapshot,
          changeReason: input.changeReason,
          changedBy: input.actorUserId,
        },
      });
      return tx.aiSystem.update({
        where: { id: current.id },
        data: { ...data, version: { increment: 1 } },
      });
    });

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SYSTEM_UPDATED,
      actor: { type: 'human', id: input.actorUserId },
      data: {
        aiSystemId: updated.id,
        slug: updated.slug,
        fromVersion: current.version,
        toVersion: updated.version,
        changedFields: Object.keys(data),
        changeReason: input.changeReason,
      },
    });

    return toSummary(updated);
  }

  /**
   * `POST /ai-systems/:id/transitions` — the only path that changes
   * `lifecycleState`.
   *
   * Order of checks is deliberate: existence, then the allowed-edge table,
   * then separation of duties. An invalid edge is reported as an invalid
   * edge even when the caller would also have failed the SoD check, so the
   * operator sees the actual problem rather than a misleading one.
   */
  async transitionState(
    tenantClient: TenantPrismaClient,
    input: TransitionAiSystemInput,
  ): Promise<AiSystemSummary> {
    const current = await tenantClient.aiSystem.findUnique({
      where: { id: input.aiSystemId },
    });
    if (current === null) {
      throw new AiSystemNotFoundError(input.aiSystemId);
    }

    const fromState = current.lifecycleState;
    const toState = input.toState;

    if (!ALLOWED_TRANSITIONS[fromState].includes(toState)) {
      throw new AiSystemInvalidTransitionError(fromState, toState);
    }

    if (SEPARATION_OF_DUTIES_EDGES.has(`${fromState}->${toState}`)) {
      await this.assertSeparationOfDuties(tenantClient, current.id, {
        toState,
        actorUserId: input.actorUserId,
      });
    }

    const updated = await tenantClient.$transaction(async (tx) => {
      await tx.aiSystemStateTransition.create({
        data: {
          aiSystemId: current.id,
          fromState,
          toState,
          reason: input.reason,
          actorId: input.actorUserId,
        },
      });
      return tx.aiSystem.update({
        where: { id: current.id },
        data: { lifecycleState: toState },
      });
    });

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SYSTEM_STATE_CHANGED,
      actor: { type: 'human', id: input.actorUserId },
      data: {
        aiSystemId: updated.id,
        slug: updated.slug,
        fromState,
        toState,
        reason: input.reason,
      },
    });

    return toSummary(updated);
  }

  /**
   * The `REVIEW -> ACTIVE` check: the activating user must not be the user
   * who most recently submitted this system for review.
   *
   * Reads the latest `DRAFT -> REVIEW` transition rather than "who created
   * the record", because a record can be reworked and resubmitted several
   * times and it is the *current* submission that is being reviewed. If no
   * such transition exists (a system that reached `REVIEW` before this
   * rule existed, or via a data fix), the check cannot be evaluated
   * against anything, so it does not block — and that is recorded in the
   * log rather than silently passed.
   */
  private async assertSeparationOfDuties(
    tenantClient: TenantPrismaClient,
    aiSystemId: string,
    input: { toState: AiSystemLifecycleState; actorUserId: string },
  ): Promise<void> {
    const submission = await tenantClient.aiSystemStateTransition.findFirst({
      where: { aiSystemId, fromState: 'DRAFT', toState: 'REVIEW' },
      orderBy: { at: 'desc' },
      select: { actorId: true },
    });

    if (submission === null) {
      this.logger.warn(
        `AI system ${aiSystemId} has no recorded DRAFT->REVIEW transition; the separation-of-duties check for ${input.toState} had no submitter to compare against and did not block.`,
      );
      return;
    }

    if (submission.actorId === input.actorUserId) {
      throw new AiSystemSeparationOfDutiesError(input.toState);
    }
  }

  /** `POST /ai-systems/:id/agents` — additive, attributed, idempotent-by-unique-constraint. */
  async linkAgent(
    tenantClient: TenantPrismaClient,
    input: {
      tenantId: string;
      aiSystemId: string;
      agentId: string;
      actorUserId: string;
    },
  ): Promise<{ linked: boolean }> {
    await this.assertAiSystemMutable(tenantClient, input.aiSystemId);

    const agent = await tenantClient.agent.findUnique({
      where: { id: input.agentId },
      select: { id: true },
    });
    if (agent === null) {
      throw new AiSystemReferenceNotFoundError('agent', input.agentId);
    }

    const existing = await tenantClient.aiSystemAgentLink.findUnique({
      where: {
        aiSystemId_agentId: {
          aiSystemId: input.aiSystemId,
          agentId: input.agentId,
        },
      },
      select: { id: true },
    });
    if (existing !== null) {
      // Already asserted. Not an error — re-linking is a no-op rather than
      // a 409, so a retried request cannot leave the caller unsure whether
      // the link exists.
      return { linked: false };
    }

    await tenantClient.aiSystemAgentLink.create({
      data: {
        aiSystemId: input.aiSystemId,
        agentId: input.agentId,
        linkedBy: input.actorUserId,
      },
    });

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SYSTEM_AGENT_LINKED,
      actor: { type: 'human', id: input.actorUserId },
      data: { aiSystemId: input.aiSystemId, agentId: input.agentId },
    });

    return { linked: true };
  }

  /** `DELETE /ai-systems/:id/agents/:agentId`. */
  async unlinkAgent(
    tenantClient: TenantPrismaClient,
    input: {
      tenantId: string;
      aiSystemId: string;
      agentId: string;
      actorUserId: string;
    },
  ): Promise<{ unlinked: boolean }> {
    await this.assertAiSystemMutable(tenantClient, input.aiSystemId);

    const deleted = await tenantClient.aiSystemAgentLink.deleteMany({
      where: { aiSystemId: input.aiSystemId, agentId: input.agentId },
    });
    if (deleted.count === 0) {
      return { unlinked: false };
    }

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SYSTEM_AGENT_UNLINKED,
      actor: { type: 'human', id: input.actorUserId },
      data: { aiSystemId: input.aiSystemId, agentId: input.agentId },
    });
    return { unlinked: true };
  }

  /** `POST /ai-systems/:id/tools`. */
  async linkTool(
    tenantClient: TenantPrismaClient,
    input: {
      tenantId: string;
      aiSystemId: string;
      toolId: string;
      actorUserId: string;
    },
  ): Promise<{ linked: boolean }> {
    await this.assertAiSystemMutable(tenantClient, input.aiSystemId);

    const tool = await tenantClient.tool.findUnique({
      where: { id: input.toolId },
      select: { id: true },
    });
    if (tool === null) {
      throw new AiSystemReferenceNotFoundError('tool', input.toolId);
    }

    const existing = await tenantClient.aiSystemToolLink.findUnique({
      where: {
        aiSystemId_toolId: {
          aiSystemId: input.aiSystemId,
          toolId: input.toolId,
        },
      },
      select: { id: true },
    });
    if (existing !== null) {
      return { linked: false };
    }

    await tenantClient.aiSystemToolLink.create({
      data: {
        aiSystemId: input.aiSystemId,
        toolId: input.toolId,
        linkedBy: input.actorUserId,
      },
    });

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SYSTEM_TOOL_LINKED,
      actor: { type: 'human', id: input.actorUserId },
      data: { aiSystemId: input.aiSystemId, toolId: input.toolId },
    });

    return { linked: true };
  }

  /** `DELETE /ai-systems/:id/tools/:toolId`. */
  async unlinkTool(
    tenantClient: TenantPrismaClient,
    input: {
      tenantId: string;
      aiSystemId: string;
      toolId: string;
      actorUserId: string;
    },
  ): Promise<{ unlinked: boolean }> {
    await this.assertAiSystemMutable(tenantClient, input.aiSystemId);

    const deleted = await tenantClient.aiSystemToolLink.deleteMany({
      where: { aiSystemId: input.aiSystemId, toolId: input.toolId },
    });
    if (deleted.count === 0) {
      return { unlinked: false };
    }

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SYSTEM_TOOL_UNLINKED,
      actor: { type: 'human', id: input.actorUserId },
      data: { aiSystemId: input.aiSystemId, toolId: input.toolId },
    });
    return { unlinked: true };
  }

  /** `GET /ai-systems/:id/versions` — the change history, newest first. */
  async listVersions(
    tenantClient: TenantPrismaClient,
    aiSystemId: string,
  ): Promise<
    {
      version: number;
      snapshot: unknown;
      changeReason: string;
      changedBy: string;
      changedAt: Date;
    }[]
  > {
    await this.assertAiSystemExists(tenantClient, aiSystemId);
    const rows = await tenantClient.aiSystemVersion.findMany({
      where: { aiSystemId },
      orderBy: { version: 'desc' },
    });
    return rows.map((row) => ({
      version: row.version,
      snapshot: row.snapshot,
      changeReason: row.changeReason,
      changedBy: row.changedBy,
      changedAt: row.changedAt,
    }));
  }

  /** `GET /ai-systems/:id/transitions` — the lifecycle history, newest first. */
  async listTransitions(
    tenantClient: TenantPrismaClient,
    aiSystemId: string,
  ): Promise<
    {
      fromState: AiSystemLifecycleState;
      toState: AiSystemLifecycleState;
      reason: string;
      actorId: string;
      at: Date;
    }[]
  > {
    await this.assertAiSystemExists(tenantClient, aiSystemId);
    const rows = await tenantClient.aiSystemStateTransition.findMany({
      where: { aiSystemId },
      orderBy: { at: 'desc' },
    });
    return rows.map((row) => ({
      fromState: row.fromState,
      toState: row.toState,
      reason: row.reason,
      actorId: row.actorId,
      at: row.at,
    }));
  }

  private async assertAiSystemExists(
    tenantClient: TenantPrismaClient,
    aiSystemId: string,
  ): Promise<void> {
    const row = await tenantClient.aiSystem.findUnique({
      where: { id: aiSystemId },
      select: { id: true },
    });
    if (row === null) {
      throw new AiSystemNotFoundError(aiSystemId);
    }
  }

  /** Existence plus the RETIRED terminal-state guard — every link/unlink mutation runs this. */
  private async assertAiSystemMutable(
    tenantClient: TenantPrismaClient,
    aiSystemId: string,
  ): Promise<void> {
    const row = await tenantClient.aiSystem.findUnique({
      where: { id: aiSystemId },
      select: { id: true, lifecycleState: true },
    });
    if (row === null) {
      throw new AiSystemNotFoundError(aiSystemId);
    }
    if (row.lifecycleState === 'RETIRED') {
      throw new AiSystemRetiredError(aiSystemId);
    }
  }

  private async assertUserExists(
    tenantClient: TenantPrismaClient,
    userId: string,
  ): Promise<void> {
    const user = await tenantClient.userProfile.findUnique({
      where: { id: userId },
      select: { id: true },
    });
    if (user === null) {
      throw new AiSystemReferenceNotFoundError('owner', userId);
    }
  }
}
