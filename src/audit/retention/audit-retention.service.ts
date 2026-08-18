import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../../generated/tenant-client/client';
import { AuditService } from '../audit.service';
import { AUDIT_EVENT_TYPES } from '../audit-event-types';
import type {
  PruneAuditEventsInput,
  PruneAuditEventsResult,
} from '../../temporal/activities/audit-retention-activities.interface';

/**
 * Phase 9b (Retention, Section 48) — the real business logic behind
 * `AuditRetentionWorkflow`'s single Activity
 * (`src/temporal/activities/audit-retention.activities.ts`), the exact
 * same "a plain injectable service holds the real logic; the Temporal
 * Activities factory is a thin adapter around it" split
 * `GrantService`/`ApprovalActivitiesFactory` already establish (Section
 * 28 — see `docs/approvals.md`).
 *
 * No API/CLI path anywhere in this codebase calls `pruneTenantAuditEvents`
 * directly outside this service's own Activity wiring and this phase's
 * tests — deleting an individual `AuditEvent` row happens *only* through
 * this governed sequence, never ad hoc.
 */
@Injectable()
export class AuditRetentionService {
  private readonly logger = new Logger(AuditRetentionService.name);

  constructor(private readonly auditService: AuditService) {}

  /**
   * 1. Finds every `AuditEvent` older than the retention window.
   * 2. If none, a genuine no-op (`prunedCount: 0`) — no anchor, no
   *    `audit.retention_executed` event; a retention run that found
   *    nothing to prune has nothing worth auditing about itself.
   * 3. Otherwise, in one transaction: writes a new `AuditChainAnchor`
   *    naming the last-to-be-pruned event's `eventHash`, then deletes the
   *    aged rows — both together, so a crash between the two never leaves
   *    an anchor with no corresponding deletion (see interface doc comment
   *    for why an occasional harmless duplicate anchor from an Activity
   *    retry is an acceptable outcome, but a "deleted without a preceding
   *    anchor" outcome never is).
   * 4. Writes `audit.retention_executed` via the *real* `AuditService.record`
   *    (not `recordSafely` — a retention run's own audit trail is not
   *    optional/best-effort the way most retrofit call sites are; a
   *    failure here should fail the whole Activity so Temporal retries
   *    it) — this new event's `previousHash` comes from the tenant's
   *    *current* `AuditChainState` exactly like any other event (Section
   *    48: "this new event naturally becomes the new chain tail" — no
   *    special-casing needed, since the events being pruned are always
   *    older than, and therefore never include, the chain's actual tail).
   */
  async pruneTenantAuditEvents(
    tenantClient: TenantPrismaClient,
    input: PruneAuditEventsInput,
  ): Promise<PruneAuditEventsResult> {
    const cutoff = new Date(Date.now() - input.retentionWindowMs);

    const agedEvents = await tenantClient.auditEvent.findMany({
      where: { timestamp: { lt: cutoff } },
      orderBy: { sequence: 'asc' },
    });

    if (agedEvents.length === 0) {
      this.logger.log(
        `Retention run for tenant "${input.tenantId}": no AuditEvent rows older than ${input.retentionWindowMs}ms — nothing to prune`,
      );
      return { prunedCount: 0, anchorHash: null, retentionEventId: null };
    }

    const lastPruned = agedEvents[agedEvents.length - 1]!;
    const anchorHash = lastPruned.eventHash;
    const prunedIds = agedEvents.map((event) => event.id);

    await tenantClient.$transaction([
      tenantClient.auditChainAnchor.create({
        data: {
          tenantId: input.tenantId,
          anchorHash,
          eventsPrunedCount: agedEvents.length,
        },
      }),
      tenantClient.auditEvent.deleteMany({ where: { id: { in: prunedIds } } }),
    ]);

    const retentionEvent = await this.auditService.record(
      tenantClient,
      input.tenantId,
      {
        eventType: AUDIT_EVENT_TYPES.AUDIT_RETENTION_EXECUTED,
        actor: { type: 'system', id: 'system:audit-retention-workflow' },
        data: {
          eventsPrunedCount: agedEvents.length,
          anchorHash,
          retentionWindowMs: input.retentionWindowMs,
          prunedWindowStart: agedEvents[0]!.timestamp.toISOString(),
          prunedWindowEnd: lastPruned.timestamp.toISOString(),
        },
      },
    );

    this.logger.log(
      `Retention run for tenant "${input.tenantId}": pruned ${agedEvents.length} AuditEvent row(s), anchored at "${anchorHash}", recorded "${retentionEvent.id}"`,
    );

    return {
      prunedCount: agedEvents.length,
      anchorHash,
      retentionEventId: retentionEvent.id,
    };
  }
}
