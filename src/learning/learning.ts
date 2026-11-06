import { HANDOVER_ACTIONS } from '../approvals/decision-rights';
import { scopeFor } from '../approvals/rule-scope';
import { SITE_CONNECT_ACTION } from '../jail/jail-sites';
import { classifyCommand } from '../policy/command-safety';
import { resourceAliases, resourceKindFor } from '../policy/resource-aliases';

/** A new device learns for this long after it is approved (decision 36). */
export const LEARNING_DAYS = 7;
/** The same line the device prompt uses for "console only": from here an action is high risk. */
export const HIGH_RISK_FROM = 50;
/** A learned pattern is suggested once it was seen this many times (same bar as the rule offer). */
export const SUGGEST_AFTER = 3;

export interface LearningHost {
  /** The first time the device was ever approved; a re-approval does not move it. */
  firstApprovedAt: Date | null;
  learningStartedAt: Date | null;
  learningOff: boolean;
}

/**
 * Learning runs 7 days from the device's FIRST approval (or an admin's restart), unless switched
 * off for the device. A device without one never learns (fail closed).
 */
export function learningWindow(
  host: LearningHost,
  days: number,
  now: Date,
): { active: boolean; endsAt: Date | null } {
  const start = host.learningStartedAt ?? host.firstApprovedAt;
  if (host.learningOff || days <= 0 || !start)
    return { active: false, endsAt: null };
  const endsAt = new Date(start.getTime() + days * 86_400_000);
  return { active: now < endsAt, endsAt };
}

const BLOCKED_ALIAS = /^(secret-file|unsafe-path|unsafe-command|git-unsafe):/;

export interface LearningCandidate {
  /** The folder, origin or tool a suggestion would cover; null for a read-only command. */
  scope: string | null;
  /** A web fetch qualifies only for a site a person has already approved on this device. */
  needsSeenSite: boolean;
}

/**
 * Whether an action that would have asked MAY be quiet while the device learns, and under which
 * scope; null means it keeps asking. Never: high risk, a secret, a secret handover, a climb out,
 * a command the shell expands, a risky git command, a new site, a file action outside a home
 * project folder (no scope: that is also every dot-folder at any depth), an MCP tool, a command that is not
 * clearly read-only. Run builds and tests are not read-only. The caller has already applied DENY,
 * kill switches and revoked-after-use blocks, and checked which ask it is (`LearningService`).
 */
export function learningCandidate(input: {
  toolId: string;
  actionId: string;
  resource: string;
  riskScore: number;
}): LearningCandidate | null {
  const a = input.actionId.toLowerCase();
  if (input.riskScore >= HIGH_RISK_FROM) return null;
  if (a === SITE_CONNECT_ACTION || HANDOVER_ACTIONS.includes(a)) return null;
  // MCP tools do anything (delete a repository, run SQL, send a message): learning covers the
  // project's own files and read-only commands, never an MCP call.
  if (a === 'mcp') return null;
  const kind = a === 'webfetch' ? 'other' : resourceKindFor(input.toolId, a);
  if (resourceAliases(input.resource, kind).some((x) => BLOCKED_ALIAS.test(x)))
    return null;
  if (kind === 'command')
    return classifyCommand(input.resource)
      ? { scope: null, needsSeenSite: false }
      : null;
  const scope = scopeFor(input.toolId, a, input.resource);
  if (scope === null) return null;
  return { scope, needsSeenSite: a === 'webfetch' };
}
