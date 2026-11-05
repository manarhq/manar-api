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
  asks?: Array<{ policyVersionId: string; matchedRule: unknown }>;
}): string {
  // Every policy that asks is part of the key, so a grant made while one policy asked never
  // answers a request that another policy also asks about.
  const parts = (
    policy.asks ?? [
      {
        policyVersionId: policy.policyVersionId ?? '',
        matchedRule: policy.matchedRule ?? null,
      },
    ]
  )
    .map((a) => `${a.policyVersionId}|${JSON.stringify(a.matchedRule)}`)
    .sort();
  return `p:${createHash('sha256').update(parts.join('\n')).digest('hex').slice(0, 24)}`;
}
