import { Injectable } from '@nestjs/common';
import {
  encodeCursor,
  parseCursor,
} from '../common/pagination/cursor-pagination';
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
  /** `ALLOW`/`DENY`/`REQUIRE_APPROVAL`/`APPROVE`/`DENY` — see `audit-search-fields.ts`'s `deriveDecision`. */
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
  constructor(
    private readonly openSearchIndexService: OpenSearchIndexService,
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
}
