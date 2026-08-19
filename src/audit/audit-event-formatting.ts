/**
 * Phase 10c — formats one already-authorized `AuditEvent` (either a raw
 * Postgres row, via `IncidentsService.summarizeIncident`, or an
 * OpenSearch-indexed `AuditEventDocument`, via `AuditSearchService`/
 * `AuditController.investigateAudit`) into a single human-readable line
 * suitable for `AiAdvisoryClient.summarizeIncident`'s `relatedEvents` /
 * `AiAdvisoryClient.investigateAudit`'s `retrievedContext`. One shared
 * function so both call sites produce the same shape rather than two
 * independently-drifting ad hoc formatters — takes only the narrow common
 * subset both source shapes have, not either model's full type.
 *
 * `data` is truncated (never dropped) to bound the size of what's sent to
 * manar-ai per event — a single pathological `data` payload must never
 * blow the gRPC message past `AiAdvisoryClient`'s tight timeout budget.
 */
const MAX_DATA_PREVIEW_LENGTH = 1000;

export function formatAuditEventForAi(event: {
  eventType: string;
  timestamp: string | Date;
  correlationId: string;
  data: unknown;
}): string {
  const timestampIso =
    event.timestamp instanceof Date
      ? event.timestamp.toISOString()
      : event.timestamp;
  const dataPreview = JSON.stringify(event.data ?? {});
  const truncated =
    dataPreview.length > MAX_DATA_PREVIEW_LENGTH
      ? `${dataPreview.slice(0, MAX_DATA_PREVIEW_LENGTH)}…`
      : dataPreview;
  return `[${timestampIso}] ${event.eventType} (correlationId=${event.correlationId}): ${truncated}`;
}
