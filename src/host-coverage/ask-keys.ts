import { createHash } from 'node:crypto';

/** The ask that comes from the risk ceiling: no rule matched. */
export const CEILING_ASK = 'ceiling';

/**
 * A policy ask is identified by the policy version and the exact rule that asked, so a grant made
 * for one rule never answers another, and republishing a policy ends the grants made for it.
 */
export function policyAskKey(policy: {
  policyVersionId?: string;
  matchedRule?: unknown;
}): string {
  return `p:${createHash('sha256')
    .update(
      `${policy.policyVersionId ?? ''}|${JSON.stringify(policy.matchedRule ?? null)}`,
    )
    .digest('hex')
    .slice(0, 24)}`;
}
