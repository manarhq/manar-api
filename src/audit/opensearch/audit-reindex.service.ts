import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../../generated/tenant-client/client';
import { OpenSearchIndexService } from './opensearch-client.service';
import { extractAuditSearchFields } from './audit-search-fields';

const PAGE_SIZE = 500;

/**
 * Phase 9b (Section 45) — the real disaster-recovery path: "Postgres
 * remains authoritative... write a real test proving this: drop/empty the
 * OpenSearch index, run a reindex operation, confirm it's fully
 * reconstructable from Postgres alone." Reads every `AuditEvent` for one
 * tenant straight from its tenant database (paginated by `sequence`, the
 * same "walk the chain in recorded order" ordering `verifyAuditChain`
 * already uses — see `docs/audit-chain.md`) and upserts each into
 * OpenSearch. Never reads from Kafka — a from-scratch reconstruction must
 * not depend on Kafka retaining history for however long it's been since
 * the index was lost.
 *
 * Shared by `pnpm manar audit:reindex` (`src/cli/commands/audit-reindex.command.ts`)
 * and this phase's own e2e test — the CLI command is a thin wrapper around
 * this service, not a second implementation of the same logic.
 */
@Injectable()
export class AuditReindexService {
  private readonly logger = new Logger(AuditReindexService.name);

  constructor(
    private readonly openSearchIndexService: OpenSearchIndexService,
  ) {}

  async reindexTenant(
    tenantClient: TenantPrismaClient,
    tenantId: string,
  ): Promise<{ count: number }> {
    let cursorSequence = -1;
    let count = 0;

    for (;;) {
      const page = await tenantClient.auditEvent.findMany({
        where: { sequence: { gt: cursorSequence } },
        orderBy: { sequence: 'asc' },
        take: PAGE_SIZE,
      });
      if (page.length === 0) break;

      // One Bulk request (and one refresh) per page, not one per event.
      await this.openSearchIndexService.bulkUpsertAuditEvents(
        page.map((event) => ({
          eventId: event.id,
          tenantId,
          sequence: event.sequence,
          eventType: event.eventType,
          correlationId: event.correlationId,
          actor: event.actor,
          timestamp: event.timestamp.toISOString(),
          data: event.data,
          previousHash: event.previousHash,
          eventHash: event.eventHash,
          // Phase 11b Part 1 — same derived search fields the live indexer
          // populates (AuditIndexerService.handleMessage); a from-scratch
          // reindex must reconstruct GET /audit's filterable fields exactly
          // as faithfully as everything else.
          ...extractAuditSearchFields(event.eventType, event.actor, event.data),
        })),
      );
      count += page.length;

      cursorSequence = page[page.length - 1]!.sequence;
      if (page.length < PAGE_SIZE) break;
    }

    this.logger.log(
      `Reindexed ${count} AuditEvent row(s) for tenant "${tenantId}" into OpenSearch`,
    );
    return { count };
  }
}
