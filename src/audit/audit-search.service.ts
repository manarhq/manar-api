import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import {
  AiAdvisoryClient,
  type AuditInvestigationAdvisory,
  type StreamHooks,
} from '../ai-advisory/ai-advisory-client.service';
import {
  maxClassification,
  type DataClassification,
} from '../common/data-classification';
import {
  encodeCursor,
  parseCursor,
} from '../common/pagination/cursor-pagination';
import { ToolRegistryService } from '../tools/tool-registry.service';
import { formatAuditEventForAi } from './audit-event-formatting';
import type { AuditEventDocument } from './opensearch/opensearch-client.service';
import { OpenSearchIndexService } from './opensearch/opensearch-client.service';

export interface AuditSearchFilters {
  /** One or more exact `eventType` values (OR'd together) — Section 46's catalog, `AUDIT_EVENT_TYPES`. */
  eventType?: string[];
  correlationId?: string;
  agentId?: string;
  taskId?: string;
  toolId?: string;
  actionId?: string;
  /** `ALLOW`/`DENY`/`APPROVAL_REQUIRED`/`APPROVE`/`DENY` — see `audit-search-fields.ts`'s `deriveDecision`. */
  decision?: string;
  riskMin?: number;
  riskMax?: number;
  /** Inclusive time-range bounds, matched against `AuditEvent.timestamp`. */
  from?: Date;
  to?: Date;
}

export interface AuditSearchInput {
  tenantId: string;
  filters: AuditSearchFilters;
  limit: number;
  cursor?: string;
}

export interface AuditSearchPage {
  items: AuditEventDocument[];
  nextCursor: string | null;
}

export interface InvestigateAuditInput {
  tenantId: string;
  /** The caller's own tenant database client — needed to resolve each retrieved AuditEvent's `ToolAction.classification` (`ToolRegistryService`). */
  tenantClient: TenantPrismaClient;
  question: string;
  filters: AuditSearchFilters;
  /** Max AuditEvents to retrieve as context — capped by the controller's own schema (50), defaulted there too. */
  contextLimit: number;
}

export interface InvestigateAuditResult {
  available: boolean;
  result: AuditInvestigationAdvisory | null;
  contextEventCount: number;
}

/**
 * `GET /audit` (Phase 11b Part 1, Section 66) — the real audit search/list
 * endpoint Phase 9a/9b never built (that phase shipped the tamper-evident
 * chain, OpenSearch indexing, and evidence export, but no plain "browse/
 * filter audit events" REST surface). Queries OpenSearch — Section 45's
 * derived, search-optimized copy — never Postgres directly (Postgres has
 * no indexes shaped for this kind of ad hoc multi-field filtering, and
 * `AuditEvent` there is the tamper-evident chain of record, not a query
 * surface — see `docs/audit-chain.md`).
 *
 * **Tenant isolation**: `tenantId` is always the caller's own
 * `AuthContext.tenant.id` (see `AuditController.search`), applied as a
 * mandatory `term` filter on every query this method builds — never a
 * client-suppliable query parameter. This is the one hard invariant this
 * endpoint must never regress: OpenSearch's single, tenant-tagged index
 * (`OpenSearchIndexService`'s own doc comment) means a missing tenant
 * filter would leak every tenant's audit history to every other tenant.
 *
 * **Pagination**: reuses this codebase's cursor convention
 * (`src/common/pagination/cursor-pagination.ts`) via OpenSearch's own
 * `search_after` mechanism — sorted by `(timestamp desc, eventId desc)`,
 * the same "compound tie-broken-by-id" shape the Prisma-backed list
 * endpoints use, just executed by OpenSearch instead of Postgres.
 */
@Injectable()
export class AuditSearchService {
  private readonly logger = new Logger(AuditSearchService.name);

  constructor(
    private readonly openSearchIndexService: OpenSearchIndexService,
    private readonly aiAdvisoryClient: AiAdvisoryClient,
    private readonly toolRegistry: ToolRegistryService,
  ) {}

  async search(input: AuditSearchInput): Promise<AuditSearchPage> {
    const must: Record<string, unknown>[] = [
      { term: { tenantId: input.tenantId } },
    ];
    const f = input.filters;

    if (f.eventType && f.eventType.length > 0) {
      must.push({ terms: { eventType: f.eventType } });
    }
    if (f.correlationId)
      must.push({ term: { correlationId: f.correlationId } });
    if (f.agentId) must.push({ term: { agentId: f.agentId } });
    if (f.taskId) must.push({ term: { taskId: f.taskId } });
    if (f.toolId) must.push({ term: { toolId: f.toolId } });
    if (f.actionId) must.push({ term: { actionId: f.actionId } });
    if (f.decision) must.push({ term: { decision: f.decision } });
    if (f.riskMin !== undefined || f.riskMax !== undefined) {
      must.push({
        range: {
          riskScore: {
            ...(f.riskMin !== undefined ? { gte: f.riskMin } : {}),
            ...(f.riskMax !== undefined ? { lte: f.riskMax } : {}),
          },
        },
      });
    }
    if (f.from || f.to) {
      must.push({
        range: {
          timestamp: {
            ...(f.from ? { gte: f.from.toISOString() } : {}),
            ...(f.to ? { lte: f.to.toISOString() } : {}),
          },
        },
      });
    }

    const cursor = parseCursor(input.cursor);
    const result = await this.openSearchIndexService.search({
      query: { bool: { must } },
      sort: [{ timestamp: 'desc' }, { eventId: 'desc' }],
      size: input.limit + 1,
      searchAfter: cursor ? [cursor.ts.toISOString(), cursor.id] : undefined,
    });

    const hasMore = result.hits.length > input.limit;
    const items = hasMore ? result.hits.slice(0, input.limit) : result.hits;
    const last = items[items.length - 1];
    const nextCursor =
      hasMore && last
        ? encodeCursor({ id: last.eventId }, new Date(last.timestamp))
        : null;

    return { items, nextCursor };
  }

  /**
   * `POST /audit/investigate` (Phase 10c) — answers a question like "why
   * was this action denied?" over the caller's own tenant's audit trail.
   * **Reuses `search` above verbatim** (`input.tenantId` flows through to
   * that method's own mandatory `term: { tenantId }` filter, applied
   * before this method ever sees a single result) rather than forking a
   * second OpenSearch query path — this is the one hard invariant Section
   * 45/66 (`search`'s own doc comment) already establishes, and this
   * method inherits it by construction, not by re-implementing it.
   * `manar-ai`'s `InvestigateAudit` RPC never runs its own retrieval (see
   * `AiAdvisoryClient.investigateAudit`'s doc comment) — every string in
   * `retrievedContext` comes from this already-tenant-scoped `search` call
   * and nothing else.
   *
   * Derives one `classification` to pass into
   * `AiAdvisoryClient.investigateAudit` — the highest-sensitivity
   * `ToolAction.classification` among the retrieved events' own
   * `toolId`/`actionId` (already indexed, top-level fields on
   * `AuditEventDocument` — no need to parse `data`) — same posture
   * `IncidentsService.summarizeIncident` establishes for the identical
   * problem, so a `RESTRICTED` action's audit trail is never investigated
   * by an external AI provider.
   */
  async investigateAudit(
    input: InvestigateAuditInput,
    /** Present on the streaming endpoint: the answer text goes to `hooks.onDelta` as it is written. */
    hooks?: StreamHooks,
  ): Promise<InvestigateAuditResult> {
    const page = await this.search({
      tenantId: input.tenantId,
      filters: input.filters,
      limit: input.contextLimit,
    });
    const events = page.items;
    const retrievedContext = events.map((event) =>
      formatAuditEventForAi(event),
    );

    const classificationCache = new Map<
      string,
      DataClassification | undefined
    >();
    const resolvedClassifications: DataClassification[] = [];
    for (const event of events) {
      if (!event.toolId || !event.actionId) continue;
      const cacheKey = `${event.toolId}:${event.actionId}`;
      if (!classificationCache.has(cacheKey)) {
        try {
          const resolved = await this.toolRegistry.findToolAction(
            input.tenantClient,
            event.toolId,
            event.actionId,
          );
          classificationCache.set(cacheKey, resolved?.action.classification);
        } catch (error) {
          this.logger.warn(
            `Could not resolve ToolAction classification for "${event.toolId}"/"${event.actionId}" while investigating audit history: ${error instanceof Error ? error.message : String(error)}`,
          );
          classificationCache.set(cacheKey, undefined);
        }
      }
      const cached = classificationCache.get(cacheKey);
      if (cached) resolvedClassifications.push(cached);
    }
    const classification = maxClassification(resolvedClassifications);

    const request = {
      question: input.question,
      retrievedContext,
      tenantId: input.tenantId,
      classification,
    };
    const advisory = hooks
      ? await this.aiAdvisoryClient.investigateAuditStream(request, hooks)
      : await this.aiAdvisoryClient.investigateAudit(request);

    return {
      available: advisory !== null,
      result: advisory,
      contextEventCount: events.length,
    };
  }
}
