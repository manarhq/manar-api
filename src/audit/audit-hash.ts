import { createHash } from 'node:crypto';
import { canonicalize } from './canonical-json';

/**
 * The one place `AuditEvent.eventHash` is ever computed — used identically
 * by `AuditService.record` (computing a *new* event's hash) and
 * `AuditService.verifyAuditChain` (recomputing every *stored* event's hash
 * to confirm it wasn't tampered with) — one implementation, so the two can
 * never drift apart from each other.
 *
 * `sha256(canonicalize({ id, eventType, correlationId, actor, timestamp,
 * data, previousHash }))` per the design spec (Section 47) — `id` and
 * `timestamp` are included in the hashed content (not just `previousHash`)
 * so that even two events with byte-identical `eventType`/`actor`/`data`
 * still hash differently, keeping every `AuditEvent` row individually
 * tamper-evident, not just the chain linkage between them.
 */
export interface HashableAuditEventContent {
  id: string;
  eventType: string;
  correlationId: string;
  actor: unknown;
  timestamp: string;
  data: unknown;
  previousHash: string | null;
}

export function computeEventHash(content: HashableAuditEventContent): string {
  return createHash('sha256')
    .update(canonicalize(content), 'utf8')
    .digest('hex');
}
