import { HANDOVER_ACTIONS } from '../approvals/decision-rights';
import { SITE_CONNECT_ACTION } from '../jail/jail-sites';
import { resourceAliases, resourceKindFor } from '../policy/resource-aliases';

/** A new device learns for this long after it is approved (decision 36). */
export const LEARNING_DAYS = 7;
/** The same line the device prompt uses for "console only": from here an action is high risk. */
export const HIGH_RISK_FROM = 50;
/** A learned pattern is suggested once it was seen this many times (same bar as the rule offer). */
export const SUGGEST_AFTER = 3;

export interface LearningHost {
  approvedAt: Date | null;
  learningStartedAt: Date | null;
  learningOff: boolean;
}

/** Learning runs from approval (or an admin's restart) for `days`, unless switched off for the device. */
export function learningWindow(
  host: LearningHost,
  days: number,
  now: Date,
): { active: boolean; endsAt: Date | null } {
  const start = host.learningStartedAt ?? host.approvedAt;
  if (host.learningOff || days <= 0 || !start)
    return { active: false, endsAt: null };
  const endsAt = new Date(start.getTime() + days * 86_400_000);
  return { active: now < endsAt, endsAt };
}

const BLOCKED_ALIAS = /^(secret-file|unsafe-path|unsafe-command|git-unsafe):/;

/**
 * Whether an action that would have asked may run unasked while the device learns. Never for
 * high risk, a secret, a handover of a secret, a path that climbs out, a command the shell
 * expands, a risky git command, or a new site. The caller has already applied DENY, kill
 * switches and revoked-after-use blocks.
 */
export function learningMayAllow(input: {
  toolId: string;
  actionId: string;
  resource: string;
  riskScore: number;
}): boolean {
  const a = input.actionId.toLowerCase();
  if (input.riskScore >= HIGH_RISK_FROM) return false;
  if (a === SITE_CONNECT_ACTION || HANDOVER_ACTIONS.includes(a)) return false;
  const kind =
    a === 'mcp' || a === 'webfetch'
      ? 'other'
      : resourceKindFor(input.toolId, a);
  return !resourceAliases(input.resource, kind).some((x) =>
    BLOCKED_ALIAS.test(x),
  );
}
