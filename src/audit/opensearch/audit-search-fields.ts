/**
 * Phase 11b Part 1 — derives the extra, *indexed* top-level fields
 * `GET /audit` filters against (agent, task, tool, action, decision, risk
 * range — Section 66's filter list) from a `DomainEventEnvelope`'s
 * `actor`/`data`, both of which are indexed `enabled: false` (opaque,
 * unfilterable — see `OpenSearchIndexService`'s doc comment for why: `data`
 * is a deliberately heterogeneous JSON blob across ~15 `eventType`s, and
 * letting OpenSearch's dynamic mapping infer a type from the first
 * document it sees for a given key risks a mapping-conflict rejection the
 * first time two `eventType`s disagree on that key's type).
 *
 * This module reads the *conventional* field names Phase 9a's own
 * `AuditService.recordSafely` call sites already use consistently across
 * the codebase (`taskId`, `toolId`, `actionId`, `agentId`/`actor.id`,
 * `riskScore`, `decision`) — see `AuthorizationService.authorize`'s
 * `audit()` closure and `GrantService`'s `approval.approved`/
 * `approval.denied` call sites for the real examples this mirrors. It
 * never *requires* any of them: an event whose `data` doesn't carry a
 * given key simply indexes that field as absent, which is exactly correct
 * (a filter on it won't match that document, which is the truthful
 * outcome — not every event type carries every dimension).
 *
 * **Known limitation**: `approval.approved`/`approval.denied` events'
 * `data` (`GrantService`) carries only `approvalRequestId`/`decision`/
 * `reason` — no `taskId`/`toolId`/`agentId` of its own. Filtering
 * `GET /audit` by agent/task/tool will therefore not surface those two
 * event types even when they really do concern that agent/task/tool;
 * enriching `GrantService`'s audit `data` payloads to carry that context
 * too is a real, separate change to an existing, already-tested audit
 * write path — out of scope for this phase's "add list endpoints"
 * mandate (see this phase's own report for why it was left as a
 * documented limitation rather than silently patched).
 */
export interface AuditSearchFields {
  agentId?: string;
  taskId?: string;
  toolId?: string;
  actionId?: string;
  /** `ALLOW`/`DENY`/`APPROVAL_REQUIRED`/`APPROVE`/`DENY` depending on eventType — see `deriveDecision`. */
  decision?: string;
  riskScore?: number;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value)
    ? value
    : undefined;
}

/**
 * `authorization.allowed`/`denied`/`pending_approval` encode their outcome
 * in `eventType` itself, not in `data.decision` — this derives the same
 * `decision` filter value from either source so `?decision=` works
 * uniformly across every event type that has a meaningful one.
 */
function deriveDecision(
  eventType: string,
  data: Record<string, unknown>,
): string | undefined {
  const explicit = asString(data.decision);
  if (explicit) return explicit;
  switch (eventType) {
    case 'authorization.allowed':
      return 'ALLOW';
    case 'authorization.denied':
      return 'DENY';
    case 'authorization.pending_approval':
      return 'APPROVAL_REQUIRED';
    default:
      return undefined;
  }
}

export function extractAuditSearchFields(
  eventType: string,
  actor: unknown,
  data: unknown,
): AuditSearchFields {
  const d: Record<string, unknown> =
    data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
  const a: Record<string, unknown> =
    actor && typeof actor === 'object'
      ? (actor as Record<string, unknown>)
      : {};

  const agentId =
    asString(d.agentId) ?? (a.type === 'agent' ? asString(a.id) : undefined);

  return {
    agentId,
    taskId: asString(d.taskId),
    toolId: asString(d.toolId),
    actionId: asString(d.actionId),
    decision: deriveDecision(eventType, d),
    riskScore: asNumber(d.riskScore),
  };
}
