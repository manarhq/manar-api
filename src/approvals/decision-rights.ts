import { SITE_CONNECT_ACTION } from '../jail/jail-sites';

export type Choice = 'approve_once' | 'approve_8h' | 'approve_always' | 'deny';

/**
 * Agent approvals scoring at or above this are high risk (the start of the console's "high" risk
 * band): an approver decides, and never the person whose agent asked. Device approvals carry their
 * own `highRisk` flag (`HIGH_RISK_SCORE` in host-approval-opener.service.ts).
 */
export const AGENT_HIGH_RISK_SCORE = 60;

/**
 * Actions whose result hands a secret to the person who approved them (ADR-0011: a temporary
 * password). Matched on the action id or the action name. `secret.use` (the device vault) releases
 * a vaulted secret to a program.
 */
export const HANDOVER_ACTIONS: readonly string[] = [
  'entra.user.password.reset',
  'entra.user.create',
  'secret.use',
];

/** Why a request is sensitive: then an approver decides, and not the requester themselves. */
export type SensitiveReason = 'high_risk' | 'handover';

/**
 * A personal workspace's owner may approve their own sensitive request only after a fresh sign-in
 * (founder decision, 3 Nov 2026): `auth_time` no older than this, checked on the server.
 */
export const STEP_UP_MAX_AGE_SECONDS = 15 * 60;

/** True when the sign-in behind this request is recent enough for a self-approval. */
export function freshSignIn(
  authTime: number | undefined,
  nowMs: number = Date.now(),
): boolean {
  return (
    authTime !== undefined && nowMs / 1000 - authTime <= STEP_UP_MAX_AGE_SECONDS
  );
}

/**
 * Why the person cannot approve: `admins_only` (the workspace setting), `needs_admin` (not an
 * approver; or sensitive and they are only the owner), `needs_another_admin` (sensitive and it is
 * their own device or agent).
 */
export type NeedsReason = 'admins_only' | 'needs_admin' | 'needs_another_admin';

export interface DecisionRights {
  /** What the person may answer. Deny stays possible for one's own request whenever deciding is. */
  choices: Choice[];
  needs: NeedsReason | null;
  why: SensitiveReason | null;
  /** Revoking only ever restricts: an approver, or the owner unless "admins only". */
  canRevoke: boolean;
  /**
   * Approving needs a fresh sign-in first (`STEP_UP_MAX_AGE_SECONDS`): the owner of a personal
   * workspace approving their own sensitive request. Deny never does.
   */
  stepUp: boolean;
}

export function sensitiveReason(input: {
  actionId: string;
  actionName?: string | null;
  highRisk?: boolean;
  riskScore?: number | null;
}): SensitiveReason | null {
  if (
    HANDOVER_ACTIONS.includes(input.actionId) ||
    (input.actionName && HANDOVER_ACTIONS.includes(input.actionName))
  )
    return 'handover';
  if (input.highRisk) return 'high_risk';
  if (input.riskScore != null && input.riskScore >= AGENT_HIGH_RISK_SCORE)
    return 'high_risk';
  return null;
}

/**
 * Who may decide what (founder decisions, 3 Nov 2026):
 * - an approver role (`admin`) decides anything, except a sensitive request from their own device
 *   or agent in a company workspace: that needs another approver (they can still deny it);
 * - the device's owner or agent's creator approves once or denies their own routine requests,
 *   unless the company workspace is "admins only"; a sensitive one they can only deny;
 * - anyone else decides nothing.
 * A personal workspace has one person, so its owner approves their own sensitive requests, but
 * only after re-confirming their sign-in (`stepUp`), and the approval is recorded as such.
 */
export function decisionRights(input: {
  admin: boolean;
  /** The person owns the device or created the agent. */
  owner: boolean;
  adminsOnly: boolean;
  company: boolean;
  sensitive: SensitiveReason | null;
  actionId: string;
}): DecisionRights {
  const { admin, owner, sensitive } = input;
  if (admin) {
    if (sensitive && owner && input.company)
      return {
        choices: ['deny'],
        needs: 'needs_another_admin',
        why: sensitive,
        canRevoke: true,
        stepUp: false,
      };
    // Personal workspace, own sensitive request: once or deny, after a fresh sign-in. No standing
    // permission (8 hours, always) is ever self-granted for something sensitive.
    if (sensitive && owner)
      return {
        choices: ['approve_once', 'deny'],
        needs: null,
        why: sensitive,
        canRevoke: true,
        stepUp: true,
      };
    return {
      choices:
        input.actionId === SITE_CONNECT_ACTION
          ? ['approve_once', 'approve_8h', 'approve_always', 'deny']
          : ['approve_once', 'approve_8h', 'deny'],
      needs: null,
      why: null,
      canRevoke: true,
      stepUp: false,
    };
  }
  if (!owner)
    return {
      choices: [],
      needs: 'needs_admin',
      why: null,
      canRevoke: false,
      stepUp: false,
    };
  if (input.adminsOnly)
    return {
      choices: [],
      needs: 'admins_only',
      why: null,
      canRevoke: false,
      stepUp: false,
    };
  if (sensitive)
    return {
      choices: ['deny'],
      needs: 'needs_admin',
      why: sensitive,
      canRevoke: true,
      stepUp: false,
    };
  return {
    choices: ['approve_once', 'deny'],
    needs: null,
    why: null,
    canRevoke: true,
    stepUp: false,
  };
}

/** The plain sentence for a refused decision. */
export function refusalMessage(rights: DecisionRights): string {
  const what =
    rights.why === 'handover'
      ? 'it hands over a secret'
      : rights.why === 'high_risk'
        ? 'it is high risk'
        : null;
  switch (rights.needs) {
    case 'admins_only':
      return 'Only a workspace approver can answer approvals in this workspace. Nothing was changed.';
    case 'needs_another_admin':
      return `This is your own request and ${what}, so another approver must answer it. Ask another approver, or deny it. Nothing was changed.`;
    case 'needs_admin':
      return what
        ? `This needs a workspace approver because ${what}. You can deny it. Nothing was changed.`
        : 'Only a workspace approver or the owner of this device or agent can answer this request. Nothing was changed.';
    default:
      return 'You can approve once or deny this request. Longer approvals and rules need a workspace approver. Nothing was changed.';
  }
}
