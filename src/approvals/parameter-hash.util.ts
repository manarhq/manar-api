import { createHash } from 'node:crypto';

export interface ParameterHashInput {
  taskId: string;
  toolId: string;
  actionId: string;
  resource: string;
  params: unknown;
}

/**
 * Recursively sorts every plain object's keys (arrays keep their original
 * order — significant there) so two structurally-equal values that merely
 * differ in key order hash identically. Deliberately minimal — not a full
 * RFC 8785 (JSON Canonicalization Scheme) implementation — mirroring
 * `src/policy/policy-content-codec.ts`'s `canonicalize` (same rationale;
 * kept as its own small local copy rather than an import from that module,
 * since it's a 15-line pure function with no reason to couple this
 * package to the policy one for it).
 */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
    );
    const sorted: Record<string, unknown> = {};
    for (const [key, val] of entries) {
      sorted[key] = canonicalize(val);
    }
    return sorted;
  }
  return value;
}

/**
 * Section 80's parameter-binding invariant, made concrete: a sha256 hex of
 * the exact `{ taskId, toolId, actionId, resource, params }` tuple an
 * `ApprovalRequest`/`AuthorizationGrant` is bound to.
 * `POST /agent/v1/tools/invoke`'s retried request (with `grantToken` set)
 * recomputes this from *its own* body — any change to any of these five
 * fields (including a params value changing, even a value nested deep
 * inside it) produces a different hash, and the grant is rejected. `params`
 * is canonicalized the same way `PolicyVersion.content` is
 * (`computeContentHash`) so byte-identical intent submitted with JSON keys
 * in a different order still hashes identically — this is about detecting
 * *semantic* changes, not incidental re-serialization order.
 */
export function computeParameterHash(input: ParameterHashInput): string {
  const canonicalJson = JSON.stringify({
    taskId: input.taskId,
    toolId: input.toolId,
    actionId: input.actionId,
    resource: input.resource,
    params: canonicalize(input.params),
  });
  return createHash('sha256').update(canonicalJson, 'utf8').digest('hex');
}
