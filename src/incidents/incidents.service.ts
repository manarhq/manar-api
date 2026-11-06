import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import {
  AiAdvisoryClient,
  type IncidentSummaryAdvisory,
  type StreamHooks,
} from '../ai-advisory/ai-advisory-client.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { extractAuditSearchFields } from '../audit/opensearch/audit-search-fields';
import { formatAuditEventForAi } from '../audit/audit-event-formatting';
import {
  maxClassification,
  type DataClassification,
} from '../common/data-classification';
import {
  CursorPage,
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import { ToolRegistryService } from '../tools/tool-registry.service';
import { IncidentNotFoundError } from './incidents.errors';
import type {
  CreateIncidentRequest,
  SummarizeIncidentRequest,
  UpdateIncidentRequest,
} from './incidents.validation';

export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'RESOLVED' | 'CLOSED';

export interface IncidentSummary {
  id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  relatedCorrelationIds: string[];
  createdBy: string;
  createdAt: Date;
  resolvedAt: Date | null;
}

export interface CreateIncidentInput extends CreateIncidentRequest {
  tenantId: string;
  createdByUserId: string;
}

export interface ListIncidentsInput {
  status?: IncidentStatus;
  severity?: IncidentSeverity;
  limit: number;
  cursor?: DecodedCursor;
}

export interface UpdateIncidentInput extends UpdateIncidentRequest {
  tenantId: string;
  incidentId: string;
  /** The authenticated caller making the change — attributed on the `incident.status_changed` audit event. */
  actorUserId: string;
}

export interface SummarizeIncidentInput extends SummarizeIncidentRequest {
  tenantId: string;
}

export interface SummarizeIncidentResult {
  available: boolean;
  result: IncidentSummaryAdvisory | null;
  contextEventCount: number;
}

function toIncidentSummary(row: {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  relatedCorrelationIds: unknown;
  createdBy: string;
  createdAt: Date;
  resolvedAt: Date | null;
}): IncidentSummary {
  return {
    id: row.id,
    title: row.title,
    description: row.description,
    severity: row.severity as IncidentSeverity,
    status: row.status as IncidentStatus,
    relatedCorrelationIds: Array.isArray(row.relatedCorrelationIds)
      ? (row.relatedCorrelationIds as string[])
      : [],
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    resolvedAt: row.resolvedAt,
  };
}

/**
 * Phase 15a (Section 70) — plain CRUD over the `Incident` model, linked to
 * existing audit data via `relatedCorrelationIds` (Phase 9a's
 * `AuditEvent.correlationId` mechanism — never a new relation table, see
 * that model's own doc comment in `prisma/tenant.prisma`). Phase 10c adds
 * `summarizeIncident` (`POST /incidents/summarize`) — an AI-advisory,
 * read-only operation that never mutates or persists onto `Incident`
 * itself (see that method's own doc comment for why).
 */
@Injectable()
export class IncidentsService {
  private readonly logger = new Logger(IncidentsService.name);

  constructor(
    private readonly auditService: AuditService,
    private readonly aiAdvisoryClient: AiAdvisoryClient,
    private readonly toolRegistry: ToolRegistryService,
  ) {}

  /** `POST /incidents`. Audited (`incident.created`). */
  async createIncident(
    tenantClient: TenantPrismaClient,
    input: CreateIncidentInput,
  ): Promise<IncidentSummary> {
    const row = await tenantClient.incident.create({
      data: {
        title: input.title,
        description: input.description,
        severity: input.severity,
        relatedCorrelationIds: input.relatedCorrelationIds ?? [],
        createdBy: input.createdByUserId,
      },
    });

    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.INCIDENT_CREATED,
      actor: { type: 'human', id: input.createdByUserId },
      data: {
        incidentId: row.id,
        severity: row.severity,
        relatedCorrelationIds: input.relatedCorrelationIds ?? [],
      },
    });

    return toIncidentSummary(row);
  }

  /** `GET /incidents` — cursor-paginated, newest first, optional `status`/`severity` filters. */
  async listIncidents(
    tenantClient: TenantPrismaClient,
    input: ListIncidentsInput,
  ): Promise<CursorPage<IncidentSummary>> {
    const where = {
      ...(input.status !== undefined ? { status: input.status } : {}),
      ...(input.severity !== undefined ? { severity: input.severity } : {}),
      ...cursorWhereClause('createdAt', input.cursor),
    };
    const rows = await tenantClient.incident.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
    });
    const page = toCursorPage(rows, input.limit, (row) => row.createdAt);
    return {
      items: page.items.map(toIncidentSummary),
      nextCursor: page.nextCursor,
    };
  }

  /** `GET /incidents/:id`. */
  async getIncidentOrThrow(
    tenantClient: TenantPrismaClient,
    incidentId: string,
  ): Promise<IncidentSummary> {
    const row = await tenantClient.incident.findUnique({
      where: { id: incidentId },
    });
    if (!row) throw new IncidentNotFoundError(incidentId);
    return toIncidentSummary(row);
  }

  /**
   * `PATCH /incidents/:id` — partial update. Setting `status: 'RESOLVED'`
   * on an incident not already `RESOLVED` stamps `resolvedAt` with the
   * current time; any other status value never touches `resolvedAt`
   * (including a later transition away from `RESOLVED` to `CLOSED` — the
   * *first* resolution time is what's operationally meaningful, see
   * `Incident.resolvedAt`'s own doc comment). Audited
   * (`incident.status_changed`) only when `status` actually changes value
   * — a PATCH that only updates title/description/severity/
   * relatedCorrelationIds is not itself a status transition, so it is not
   * separately audited this phase (the `Incident` row's own update is the
   * durable record; Section 70 asks specifically for create/status-change
   * auditing).
   */
  async updateIncident(
    tenantClient: TenantPrismaClient,
    input: UpdateIncidentInput,
  ): Promise<IncidentSummary> {
    const existing = await tenantClient.incident.findUnique({
      where: { id: input.incidentId },
    });
    if (!existing) throw new IncidentNotFoundError(input.incidentId);

    const statusChanged =
      input.status !== undefined && input.status !== existing.status;
    const transitioningIntoResolved =
      statusChanged && input.status === 'RESOLVED';

    const row = await tenantClient.incident.update({
      where: { id: input.incidentId },
      data: {
        ...(input.title !== undefined ? { title: input.title } : {}),
        ...(input.description !== undefined
          ? { description: input.description }
          : {}),
        ...(input.severity !== undefined ? { severity: input.severity } : {}),
        ...(input.status !== undefined ? { status: input.status } : {}),
        ...(input.relatedCorrelationIds !== undefined
          ? { relatedCorrelationIds: input.relatedCorrelationIds }
          : {}),
        ...(transitioningIntoResolved ? { resolvedAt: new Date() } : {}),
      },
    });

    if (statusChanged) {
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.INCIDENT_STATUS_CHANGED,
        actor: { type: 'human', id: input.actorUserId },
        data: {
          incidentId: row.id,
          previousStatus: existing.status,
          newStatus: row.status,
        },
      });
    }

    return toIncidentSummary(row);
  }

  /**
   * `POST /incidents/summarize` (Phase 10c) — gathers caller-specified
   * context (an existing `Incident`'s title/description/related
   * `AuditEvent`s and/or explicit `AuditEvent` ids and/or free-text
   * `description`) and calls `AiAdvisoryClient.summarizeIncident`. Read-
   * only, never persisted onto `Incident` (see this phase's own report for
   * the reasoning: `Incident` is a model Phase 15a owns, and a synthesized,
   * potentially-stale AI summary is a fundamentally different kind of data
   * than the plain CRUD fields that model carries today — every summary is
   * intentionally re-derivable and re-runnable, not a durable fact).
   *
   * **Tenant scoping**: every lookup here (`incident.findUnique`,
   * `auditEvent.findMany`) runs against `tenantClient`, the caller's own
   * tenant's physically separate Postgres database
   * (`TenantDatabaseManager.getClient(auth.tenant.id)` —
   * docs/tenant-isolation.md) — an `incidentId`/`auditEventIds` entry
   * belonging to a different tenant simply doesn't exist in this query and
   * is never fetched, the same mechanism `IncidentsService`'s other methods
   * already rely on.
   *
   * **Classification**: derives one `classification` to pass into
   * `AiAdvisoryClient.summarizeIncident` — the highest-sensitivity
   * `ToolAction.classification` among every included `AuditEvent`'s
   * resolved `{toolId, actionId}` (an event with no resolvable
   * `ToolAction`, or none at all, leaves this `undefined`, same as an
   * unregistered action anywhere else in this codebase) — so a `RESTRICTED`
   * action's audit trail is never summarized by an external AI provider,
   * exactly like every other `AiAdvisoryClient` call site (see
   * docs/data-classification.md).
   */
  async summarizeIncident(
    tenantClient: TenantPrismaClient,
    input: SummarizeIncidentInput,
    /** Present on the streaming endpoint: the summary text goes to `hooks.onDelta` as it is written. */
    hooks?: StreamHooks,
  ): Promise<SummarizeIncidentResult> {
    let baseDescription = input.description ?? '';
    let relatedCorrelationIds: string[] = [];

    if (input.incidentId !== undefined) {
      const incident = await tenantClient.incident.findUnique({
        where: { id: input.incidentId },
      });
      if (!incident) throw new IncidentNotFoundError(input.incidentId);
      const incidentContext = `${incident.title}\n${incident.description}`;
      baseDescription = baseDescription
        ? `${incidentContext}\n\n${baseDescription}`
        : incidentContext;
      relatedCorrelationIds = Array.isArray(incident.relatedCorrelationIds)
        ? (incident.relatedCorrelationIds as string[])
        : [];
    }

    const eventsById = new Map<
      string,
      {
        eventType: string;
        timestamp: Date;
        correlationId: string;
        data: unknown;
      }
    >();

    if (relatedCorrelationIds.length > 0) {
      const events = await tenantClient.auditEvent.findMany({
        where: { correlationId: { in: relatedCorrelationIds } },
        orderBy: { sequence: 'asc' },
      });
      for (const event of events) eventsById.set(event.id, event);
    }
    if (input.auditEventIds && input.auditEventIds.length > 0) {
      const events = await tenantClient.auditEvent.findMany({
        where: { id: { in: input.auditEventIds } },
        orderBy: { sequence: 'asc' },
      });
      for (const event of events) eventsById.set(event.id, event);
    }

    const events = [...eventsById.values()];
    const relatedEvents = events.map((event) => formatAuditEventForAi(event));

    const resolvedClassifications: DataClassification[] = [];
    for (const event of events) {
      const fields = extractAuditSearchFields(
        event.eventType,
        undefined,
        event.data,
      );
      if (!fields.toolId || !fields.actionId) continue;
      try {
        const resolved = await this.toolRegistry.findToolAction(
          tenantClient,
          fields.toolId,
          fields.actionId,
        );
        if (resolved)
          resolvedClassifications.push(resolved.action.classification);
      } catch (error) {
        this.logger.warn(
          `Could not resolve ToolAction classification for "${fields.toolId}"/"${fields.actionId}" while summarizing an incident: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    const classification = maxClassification(resolvedClassifications);

    const request = {
      description: baseDescription,
      relatedEvents,
      tenantId: input.tenantId,
      classification,
    };
    const advisory = hooks
      ? await this.aiAdvisoryClient.summarizeIncidentStream(request, hooks)
      : await this.aiAdvisoryClient.summarizeIncident(request);

    return {
      available: advisory !== null,
      result: advisory,
      contextEventCount: events.length,
    };
  }
}
