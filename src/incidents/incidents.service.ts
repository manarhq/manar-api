import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  CursorPage,
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import { IncidentNotFoundError } from './incidents.errors';
import type {
  CreateIncidentRequest,
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
 * that model's own doc comment in `prisma/tenant.prisma`). No AI-generated
 * summarization this phase (Phase 10c, out of scope — see
 * docs/data-classification.md's sibling doc, docs/compliance-mapping.md,
 * for this phase's own explicit non-goals).
 */
@Injectable()
export class IncidentsService {
  constructor(private readonly auditService: AuditService) {}

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
}
