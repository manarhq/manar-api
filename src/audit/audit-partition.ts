import { createHash } from 'node:crypto';
import type { AuditActor } from './audit-event-types';

/**
 * How many independent hash chains each tenant's audit log is split into
 * (docs/audit-chain.md). One chain per tenant serialised every write on a
 * single locked row (~45–50 events/s); 64 lets unrelated agents append in
 * parallel while each agent's own events stay strictly ordered.
 */
export const AUDIT_PARTITIONS = 64;

/**
 * The partition an event belongs to, keyed by the agent it is about: the
 * actor when the actor is an agent, otherwise `data.agentId` when the event
 * names one (an approver's decision on an agent's request lands next to that
 * agent's own events), otherwise the actor id.
 */
export function partitionFor(actor: AuditActor, data: unknown): number {
  const agentId =
    data !== null && typeof data === 'object'
      ? (data as { agentId?: unknown }).agentId
      : undefined;
  const key =
    actor.type === 'agent'
      ? actor.id
      : typeof agentId === 'string' && agentId !== ''
        ? agentId
        : actor.id;
  return (
    createHash('sha256').update(key, 'utf8').digest().readUInt32BE(0) %
    AUDIT_PARTITIONS
  );
}
