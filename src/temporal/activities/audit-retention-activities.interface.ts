/**
 * The Activity contract `AuditRetentionWorkflow` calls through
 * (`proxyActivities<AuditRetentionActivities>(...)`) — `import type` only
 * from the workflow file, exactly the same "erased from the workflow's
 * compiled bundle" pattern `approval-activities.interface.ts` establishes
 * (Section 28: workflow code contains no I/O; the real implementation, in
 * `audit-retention.activities.ts`, is Nest/Prisma code that runs only in
 * the separate worker process).
 */

export interface PruneAuditEventsInput {
  tenantId: string;
  /** How far back "now" the retention window extends — events older than this are pruned. Default `DEFAULT_AUDIT_RETENTION_WINDOW_MS` (30 days). */
  retentionWindowMs: number;
}

export interface PruneAuditEventsResult {
  /** How many `AuditEvent` rows this run deleted — `0` if nothing was old enough (a genuine no-op: no anchor written, no `audit.retention_executed` event). */
  prunedCount: number;
  /** The last `AuditChainAnchor.anchorHash` this run wrote — `null` when `prunedCount` is `0`. */
  anchorHash: string | null;
  /** One anchor per pruned audit partition (empty when `prunedCount` is `0`). */
  anchors: { partition: number; anchorHash: string }[];
  /** The new `audit.retention_executed` `AuditEvent.id` this run wrote — `null` when `prunedCount` is `0`. */
  retentionEventId: string | null;
}

export interface AuditRetentionActivities {
  /**
   * Finds `AuditEvent` rows older than the retention window, records the
   * last-to-be-pruned one's `eventHash` as a new `AuditChainAnchor`,
   * deletes the aged rows, and writes a new `audit.retention_executed`
   * `AuditEvent` (which becomes the new chain tail) — Section 48's full
   * sequence. Idempotent in the sense that matters for a Temporal Activity
   * retry: re-running this after a partial failure only ever operates on
   * whatever events are *still* older than the window at that moment
   * (already-deleted rows can't be found again), so a retry can at worst
   * produce an extra, harmless `AuditChainAnchor`/`audit.retention_executed`
   * pair for a smaller remaining batch — it can never delete a row twice,
   * corrupt the chain, or lose an anchor for a genuinely-pruned segment.
   */
  pruneAuditEvents(
    input: PruneAuditEventsInput,
  ): Promise<PruneAuditEventsResult>;
}
