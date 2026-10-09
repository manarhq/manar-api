import { randomBytes } from 'node:crypto';
import type { ToolInvocationResult } from './tool-protocol-adapter.interface';

/**
 * The Microsoft action catalog (Phase 2, ADR-0004): every Graph and
 * Defender for Endpoint call Manar can make on a customer's tenant, fixed in
 * code. `MicrosoftToolAdapter` only executes an action named here, builds the
 * request only from this definition, and validates `params` against the
 * schema here, not against the `ToolAction` row (which the seed writes from
 * this same list, so policy, risk and the tool manifest see the same flags).
 *
 * The call's target is always the authorized `resource` (a user, machine,
 * incident, alert or machine-action id), never a value inside `params`: the
 * task's resource selectors and the approval grant are bound to `resource`,
 * so an agent cannot authorize one user and act on another.
 *
 * `permissions` are the Microsoft application permissions each action needs
 * on the customer's app registration (least privileged first). They are
 * taken from Microsoft's public documentation and have NOT been verified
 * against a live tenant yet.
 */

export type MicrosoftApi = 'graph' | 'defender';

export const MICROSOFT_SCOPES: Record<MicrosoftApi, string> = {
  graph: 'https://graph.microsoft.com/.default',
  defender: 'https://api.securitycenter.microsoft.com/.default',
};

export interface MicrosoftRequest {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  /** Relative to the tool's base endpoint; built from validated segments only. */
  path: string;
  query?: Record<string, string>;
  body?: unknown;
}

export interface MicrosoftActionDef {
  name: string;
  api: MicrosoftApi;
  description: string;
  mutating: boolean;
  destructive: boolean;
  riskBaseScore: number;
  permissions: string[];
  /** What `resource` must look like for this action. */
  resource: RegExp;
  inputSchema: Record<string, unknown>;
  /** Clamps the policy's risk score up to this (create/offboard: high). */
  riskFloor?: number;
  /** A single-request action. */
  build?(resource: string, params: Record<string, unknown>): MicrosoftRequest;
  /**
   * A multi-step action: sends its requests through `call`, one by one.
   * Steps that have already changed something are not undone when a later
   * one fails; `steps()` turns that into a partial outcome.
   */
  run?(
    resource: string,
    params: Record<string, unknown>,
    call: MicrosoftCall,
  ): Promise<MicrosoftOutcome>;
}

/** One request's outcome, as the adapter maps it (retries, UNKNOWN). */
export type MicrosoftOutcome = ToolInvocationResult;

export type MicrosoftCall = (
  request: MicrosoftRequest,
) => Promise<MicrosoftOutcome>;

const GUID =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
/** Object id or user principal name. The first character excludes `.`/`..` path segments. */
const USER = /^[A-Za-z0-9][A-Za-z0-9@._-]{0,255}$/;
const MACHINE = /^[0-9a-fA-F]{40}$/;
const INCIDENT = /^[0-9]{1,20}$/;
const ALERT = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
/** List actions ignore `resource`; it is still authorized, so any selector value works. */
const ANY = /^.+$/;

const noParams = { type: 'object', additionalProperties: false };
const topParams = {
  type: 'object',
  additionalProperties: false,
  properties: { top: { type: 'integer', minimum: 1, maximum: 50 } },
};
const comment = { type: 'string', minLength: 1, maxLength: 1000 };
const commentOnly = {
  type: 'object',
  additionalProperties: false,
  required: ['comment'],
  properties: { comment },
};

const seg = encodeURIComponent;
const topQuery = (params: Record<string, unknown>) => ({
  $top: String(typeof params.top === 'number' ? params.top : 10),
});

/**
 * A temporary password generated inside Manar. It reaches Graph and, when a
 * person approved the action, that person (through the broker's handover,
 * ADR-0011); never the agent. The suffix meets Entra's complexity rule
 * (3 of 4 character classes).
 */
function temporaryPassword(): string {
  return `${randomBytes(18).toString('base64url')}Aa1!`;
}

/** `<group object id>:<user object id or UPN>`: both targets of a membership change are authorized. */
const MEMBERSHIP =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}:[A-Za-z0-9][A-Za-z0-9@._-]{0,255}$/;
/** A new user's UPN: `alias@domain`. */
const NEW_UPN =
  /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}@[A-Za-z0-9][A-Za-z0-9.-]{0,189}$/;

const GRAPH_OBJECT = 'https://graph.microsoft.com/v1.0/directoryObjects/';

/**
 * Runs the steps of a multi-step action in order and stops at the first
 * failure. If nothing changed yet, the failure is returned as it is. If an
 * earlier mutating step already changed something, the outcome is UNKNOWN
 * ("partial: ..."), so it is reconciled by a person and never retried.
 */
async function steps(
  call: MicrosoftCall,
  list: { name: string; request: MicrosoftRequest }[],
): Promise<{ done: string[]; failure?: MicrosoftOutcome }> {
  const done: string[] = [];
  for (const step of list) {
    const result = await call(step.request);
    if (!result.success)
      return { done, failure: partial(done, step.name, result) };
    if (step.request.method !== 'GET') done.push(step.name);
  }
  return { done };
}

function partial(
  done: string[],
  failed: string,
  result: MicrosoftOutcome,
): MicrosoftOutcome {
  if (done.length === 0) return result;
  return {
    success: false,
    errorMessage: `partial: done ${done.join(', ')}; ${failed} failed (${result.errorMessage ?? 'error'})`,
    outcomeUnknown: true,
  };
}

/** The user's object id: a GUID as it is, a UPN looked up (memberships and `$ref` need the id). */
async function userObjectId(
  call: MicrosoftCall,
  user: string,
): Promise<{ id?: string; failure?: MicrosoftOutcome }> {
  if (GUID.test(user)) return { id: user };
  const got = await call({
    method: 'GET',
    path: `users/${seg(user)}`,
    query: { $select: 'id' },
  });
  const id = (got.data as { id?: unknown } | undefined)?.id;
  if (!got.success) return { failure: got };
  return typeof id === 'string' && GUID.test(id)
    ? { id }
    : { failure: { success: false, errorMessage: 'user_id_not_returned' } };
}

function splitMembership(resource: string): [string, string] {
  const at = resource.indexOf(':');
  return [resource.slice(0, at), resource.slice(at + 1)];
}

/**
 * Authentication method types Graph can delete, by `@odata.type`, in the
 * order they are removed. Phone numbers go last, mobile last of all: Entra
 * refuses to remove a default phone method while others remain.
 */
const AUTH_METHOD_SEGMENTS: [string, string][] = [
  [
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
    'microsoftAuthenticatorMethods',
  ],
  ['#microsoft.graph.softwareOathAuthenticationMethod', 'softwareOathMethods'],
  ['#microsoft.graph.fido2AuthenticationMethod', 'fido2Methods'],
  [
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
    'windowsHelloForBusinessMethods',
  ],
  [
    '#microsoft.graph.platformCredentialAuthenticationMethod',
    'platformCredentialMethods',
  ],
  [
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod',
    'temporaryAccessPassMethods',
  ],
  ['#microsoft.graph.emailAuthenticationMethod', 'emailMethods'],
  ['#microsoft.graph.phoneAuthenticationMethod', 'phoneMethods'],
];
/** Phone method ids are fixed by Graph; mobile is removed last. */
const MOBILE_PHONE_METHOD = '3179e48a-750b-4051-897c-87b9720928f7';

/** What offboarding cannot do through this app, said plainly in its result. */
export const OFFBOARD_HANDOVER_DECLARED_ONLY = {
  mailbox:
    'declared-only: mailbox delegation or conversion to a shared mailbox is an Exchange Online operation, not Microsoft Graph; not done',
  oneDrive:
    "declared-only: giving a manager access to the user's OneDrive needs Sites.FullControl.All, which this app does not hold; not done",
} as const;

const machineAction = (
  name: string,
  endpoint: string,
  def: Pick<
    MicrosoftActionDef,
    'description' | 'destructive' | 'riskBaseScore' | 'permissions'
  > & {
    inputSchema?: Record<string, unknown>;
    body?: (params: Record<string, unknown>) => Record<string, unknown>;
  },
): MicrosoftActionDef => ({
  name,
  api: 'defender',
  mutating: true,
  resource: MACHINE,
  inputSchema: def.inputSchema ?? commentOnly,
  description: def.description,
  destructive: def.destructive,
  riskBaseScore: def.riskBaseScore,
  permissions: def.permissions,
  build: (resource, params) => ({
    method: 'POST',
    path: `machines/${seg(resource)}/${endpoint}`,
    body: { Comment: params.comment, ...def.body?.(params) },
  }),
});

export const MICROSOFT_ACTIONS: readonly MicrosoftActionDef[] = [
  // ---- Microsoft Graph: reads ----
  {
    name: 'entra.user.get',
    api: 'graph',
    description: 'Read an Entra ID user (id, UPN, display name, enabled).',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['User.Read.All'],
    resource: USER,
    inputSchema: noParams,
    build: (r) => ({
      method: 'GET',
      path: `users/${seg(r)}`,
      query: { $select: 'id,displayName,userPrincipalName,accountEnabled' },
    }),
  },
  {
    name: 'entra.user.signins.list',
    api: 'graph',
    description: "List a user's recent sign-ins (resource: user object id).",
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['AuditLog.Read.All', 'Directory.Read.All'],
    resource: GUID,
    inputSchema: topParams,
    build: (r, p) => ({
      method: 'GET',
      path: 'auditLogs/signIns',
      query: { $filter: `userId eq '${r}'`, ...topQuery(p) },
    }),
  },
  {
    name: 'entra.user.risk.get',
    api: 'graph',
    description:
      "Read a user's Identity Protection risk (resource: user object id).",
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['IdentityRiskyUser.Read.All'],
    resource: GUID,
    inputSchema: noParams,
    build: (r) => ({
      method: 'GET',
      path: `identityProtection/riskyUsers/${seg(r)}`,
    }),
  },
  {
    name: 'security.incident.list',
    api: 'graph',
    description: 'List Microsoft Defender XDR incidents.',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['SecurityIncident.Read.All'],
    resource: ANY,
    inputSchema: topParams,
    build: (_r, p) => ({
      method: 'GET',
      path: 'security/incidents',
      query: topQuery(p),
    }),
  },
  {
    name: 'security.incident.get',
    api: 'graph',
    description: 'Read one Defender XDR incident, optionally with its alerts.',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['SecurityIncident.Read.All'],
    resource: INCIDENT,
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: { expandAlerts: { type: 'boolean' } },
    },
    build: (r, p) => ({
      method: 'GET',
      path: `security/incidents/${seg(r)}`,
      ...(p.expandAlerts ? { query: { $expand: 'alerts' } } : {}),
    }),
  },
  {
    name: 'security.alert.list',
    api: 'graph',
    description: 'List Defender XDR alerts (alerts_v2).',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['SecurityAlert.Read.All'],
    resource: ANY,
    inputSchema: topParams,
    build: (_r, p) => ({
      method: 'GET',
      path: 'security/alerts_v2',
      query: topQuery(p),
    }),
  },
  {
    name: 'security.alert.get',
    api: 'graph',
    description: 'Read one Defender XDR alert (alerts_v2).',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['SecurityAlert.Read.All'],
    resource: ALERT,
    inputSchema: noParams,
    build: (r) => ({ method: 'GET', path: `security/alerts_v2/${seg(r)}` }),
  },

  // ---- Microsoft Graph: identity containment ----
  {
    name: 'entra.user.disable',
    api: 'graph',
    description:
      'Disable an Entra ID user account (accountEnabled=false). Reversible with entra.user.enable.',
    mutating: true,
    destructive: true,
    riskBaseScore: 40,
    permissions: ['User.EnableDisableAccount.All', 'User.Read.All'],
    resource: USER,
    inputSchema: noParams,
    build: (r) => ({
      method: 'PATCH',
      path: `users/${seg(r)}`,
      body: { accountEnabled: false },
    }),
  },
  {
    name: 'entra.user.enable',
    api: 'graph',
    description: 'Re-enable an Entra ID user account (accountEnabled=true).',
    mutating: true,
    destructive: false,
    riskBaseScore: 20,
    permissions: ['User.EnableDisableAccount.All', 'User.Read.All'],
    resource: USER,
    inputSchema: noParams,
    build: (r) => ({
      method: 'PATCH',
      path: `users/${seg(r)}`,
      body: { accountEnabled: true },
    }),
  },
  {
    name: 'entra.user.sessions.revoke',
    api: 'graph',
    description:
      "Revoke all of a user's refresh tokens and session cookies (revokeSignInSessions). Cannot be undone.",
    mutating: true,
    destructive: true,
    riskBaseScore: 30,
    permissions: ['User.RevokeSessions.All'],
    resource: USER,
    inputSchema: noParams,
    build: (r) => ({
      method: 'POST',
      path: `users/${seg(r)}/revokeSignInSessions`,
    }),
  },
  {
    name: 'entra.user.password.reset',
    api: 'graph',
    description:
      'Set a temporary password generated by Manar and require a change at next sign-in. The password goes only to the person who approved the action (collected once from Manar), never to the agent. Without an approver it is discarded, which locks the current password holder out.',
    mutating: true,
    destructive: true,
    riskBaseScore: 40,
    permissions: ['User-PasswordProfile.ReadWrite.All'],
    resource: USER,
    inputSchema: noParams,
    run: async (r, _p, call) => {
      const password = temporaryPassword();
      const result = await call({
        method: 'PATCH',
        path: `users/${seg(r)}`,
        body: {
          passwordProfile: { password, forceChangePasswordNextSignIn: true },
        },
      });
      return result.success
        ? {
            success: true,
            data: { passwordReset: true, forceChangePasswordNextSignIn: true },
            handover: { temporaryPassword: password },
          }
        : result;
    },
  },
  {
    name: 'entra.user.mfa.reset',
    api: 'graph',
    description:
      "Remove the user's registered authentication methods (authenticator app, phone, FIDO2, email, OATH, Windows Hello, temporary access pass; the password stays) and revoke sessions, so the user must register MFA again at next sign-in where MFA is required. Removal is one call per method and is not atomic.",
    mutating: true,
    destructive: true,
    riskBaseScore: 40,
    permissions: [
      'UserAuthenticationMethod.ReadWrite.All',
      'User.RevokeSessions.All',
    ],
    resource: USER,
    inputSchema: noParams,
    run: async (r, _p, call) => {
      const listed = await call({
        method: 'GET',
        path: `users/${seg(r)}/authentication/methods`,
      });
      if (!listed.success) return listed;
      const methods = (
        ((listed.data as { value?: unknown } | undefined)?.value ?? []) as {
          id?: unknown;
          '@odata.type'?: unknown;
        }[]
      ).filter((m) => typeof m.id === 'string');
      const plan: { name: string; request: MicrosoftRequest }[] = [];
      const kept: string[] = [];
      for (const [type, segment] of AUTH_METHOD_SEGMENTS) {
        const ofType = methods
          .filter((m) => m['@odata.type'] === type)
          .sort((a) => (a.id === MOBILE_PHONE_METHOD ? 1 : -1));
        for (const m of ofType) {
          plan.push({
            name: segment,
            request: {
              method: 'DELETE',
              path: `users/${seg(r)}/authentication/${segment}/${seg(String(m.id))}`,
            },
          });
        }
      }
      for (const m of methods) {
        const type = String(m['@odata.type']);
        if (!AUTH_METHOD_SEGMENTS.some(([t]) => t === type))
          kept.push(type.replace('#microsoft.graph.', ''));
      }
      plan.push({
        name: 'sessions.revoke',
        request: {
          method: 'POST',
          path: `users/${seg(r)}/revokeSignInSessions`,
        },
      });
      const { done, failure } = await steps(call, plan);
      if (failure) return failure;
      return {
        success: true,
        data: {
          methodsRemoved: done.filter((d) => d !== 'sessions.revoke'),
          methodsKept: kept,
          sessionsRevoked: true,
        },
      };
    },
  },
  {
    name: 'entra.user.unlock',
    api: 'graph',
    description:
      'Let a locked-out user sign in again: re-enable the account (accountEnabled=true). Graph has no call that clears an Entra smart lockout; that lockout ends on its own after its lockout period. Pair with entra.user.password.reset when the password is the problem.',
    mutating: true,
    destructive: false,
    riskBaseScore: 20,
    permissions: ['User.EnableDisableAccount.All', 'User.Read.All'],
    resource: USER,
    inputSchema: noParams,
    build: (r) => ({
      method: 'PATCH',
      path: `users/${seg(r)}`,
      body: { accountEnabled: true },
    }),
  },
  {
    name: 'entra.group.members.list',
    api: 'graph',
    description: "List a group's members (resource: group object id).",
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['GroupMember.Read.All'],
    resource: GUID,
    inputSchema: topParams,
    build: (r, p) => ({
      method: 'GET',
      path: `groups/${seg(r)}/members`,
      query: { $select: 'id,displayName,userPrincipalName', ...topQuery(p) },
    }),
  },
  {
    name: 'entra.group.member.add',
    api: 'graph',
    description:
      'Add a user to a group (resource: "<group object id>:<user object id or UPN>"). Reversible with entra.group.member.remove.',
    mutating: true,
    destructive: false,
    riskBaseScore: 20,
    permissions: ['GroupMember.ReadWrite.All', 'User.Read.All'],
    resource: MEMBERSHIP,
    inputSchema: noParams,
    run: async (r, _p, call) => {
      const [group, user] = splitMembership(r);
      const { id, failure } = await userObjectId(call, user);
      if (!id) return failure!;
      const added = await call({
        method: 'POST',
        path: `groups/${seg(group)}/members/$ref`,
        body: { '@odata.id': `${GRAPH_OBJECT}${id}` },
      });
      return added.success
        ? { success: true, data: { added: true, groupId: group, userId: id } }
        : added;
    },
  },
  {
    name: 'entra.group.member.remove',
    api: 'graph',
    description:
      'Remove a user from a group (resource: "<group object id>:<user object id or UPN>").',
    mutating: true,
    destructive: true,
    riskBaseScore: 25,
    permissions: ['GroupMember.ReadWrite.All', 'User.Read.All'],
    resource: MEMBERSHIP,
    inputSchema: noParams,
    run: async (r, _p, call) => {
      const [group, user] = splitMembership(r);
      const { id, failure } = await userObjectId(call, user);
      if (!id) return failure!;
      const removed = await call({
        method: 'DELETE',
        path: `groups/${seg(group)}/members/${seg(id)}/$ref`,
      });
      return removed.success
        ? { success: true, data: { removed: true, groupId: group, userId: id } }
        : removed;
    },
  },
  {
    name: 'entra.user.create',
    api: 'graph',
    description:
      'Joiner: create a user (resource: the new UPN), disabled unless accountEnabled is true, with a temporary password Manar generates that goes only to the approving person and must be changed at first sign-in. Add groups with entra.group.member.add.',
    mutating: true,
    destructive: false,
    riskBaseScore: 50,
    riskFloor: 70,
    permissions: ['User.ReadWrite.All'],
    resource: NEW_UPN,
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['displayName'],
      properties: {
        displayName: { type: 'string', minLength: 1, maxLength: 256 },
        accountEnabled: { type: 'boolean' },
        jobTitle: { type: 'string', minLength: 1, maxLength: 128 },
        department: { type: 'string', minLength: 1, maxLength: 64 },
        usageLocation: { type: 'string', pattern: '^[A-Z]{2}$' },
      },
    },
    run: async (r, p, call) => {
      const password = temporaryPassword();
      const created = await call({
        method: 'POST',
        path: 'users',
        body: {
          userPrincipalName: r,
          mailNickname: r
            .slice(0, r.indexOf('@'))
            .replace(/[^A-Za-z0-9._-]/g, ''),
          displayName: p.displayName,
          accountEnabled: p.accountEnabled === true,
          ...(p.jobTitle ? { jobTitle: p.jobTitle } : {}),
          ...(p.department ? { department: p.department } : {}),
          ...(p.usageLocation ? { usageLocation: p.usageLocation } : {}),
          passwordProfile: { password, forceChangePasswordNextSignIn: true },
        },
      });
      if (!created.success) return created;
      const u = (created.data ?? {}) as Record<string, unknown>;
      return {
        success: true,
        data: {
          id: u.id,
          userPrincipalName: u.userPrincipalName,
          displayName: u.displayName,
          accountEnabled: u.accountEnabled ?? p.accountEnabled === true,
        },
        handover: { temporaryPassword: password },
      };
    },
  },
  {
    name: 'entra.user.offboard',
    api: 'graph',
    description:
      'Leaver: disable the account, revoke all sessions, and remove the user from every group Graph can change. Mailbox and OneDrive handover are declared-only (not done; the result says so). Not undone automatically: re-enable with entra.user.enable and re-add groups by hand.',
    mutating: true,
    destructive: true,
    riskBaseScore: 60,
    riskFloor: 80,
    permissions: [
      'User.EnableDisableAccount.All',
      'User.RevokeSessions.All',
      'GroupMember.ReadWrite.All',
      'User.Read.All',
    ],
    resource: USER,
    inputSchema: noParams,
    run: async (r, _p, call) => {
      const { id, failure } = await userObjectId(call, r);
      if (!id) return failure!;
      const groups = await call({
        method: 'GET',
        path: `users/${seg(id)}/memberOf/microsoft.graph.group`,
        query: { $select: 'id,displayName,groupTypes,mailEnabled' },
      });
      if (!groups.success) return groups;
      const memberOf = (
        ((groups.data as { value?: unknown } | undefined)?.value ?? []) as {
          id?: unknown;
          groupTypes?: unknown;
        }[]
      ).filter((g) => typeof g.id === 'string' && GUID.test(g.id));
      // Dynamic groups follow their rule; Graph cannot remove a member from them.
      const dynamic = memberOf.filter(
        (g) =>
          Array.isArray(g.groupTypes) &&
          g.groupTypes.includes('DynamicMembership'),
      );
      const removable = memberOf.filter((g) => !dynamic.includes(g));
      const { done, failure: failed } = await steps(call, [
        {
          name: 'disable',
          request: {
            method: 'PATCH',
            path: `users/${seg(id)}`,
            body: { accountEnabled: false },
          },
        },
        {
          name: 'sessions.revoke',
          request: {
            method: 'POST',
            path: `users/${seg(id)}/revokeSignInSessions`,
          },
        },
        ...removable.map((g) => ({
          name: `group.remove ${String(g.id)}`,
          request: {
            method: 'DELETE' as const,
            path: `groups/${seg(String(g.id))}/members/${seg(id)}/$ref`,
          },
        })),
      ]);
      if (failed) return failed;
      return {
        success: true,
        data: {
          userId: id,
          disabled: true,
          sessionsRevoked: true,
          groupsRemoved: done
            .filter((d) => d.startsWith('group.remove '))
            .map((d) => d.slice(13)),
          groupsKeptDynamic: dynamic.map((g) => String(g.id)),
          handover: OFFBOARD_HANDOVER_DECLARED_ONLY,
        },
      };
    },
  },
  {
    name: 'entra.user.risk.confirmCompromised',
    api: 'graph',
    description:
      'Mark a user as confirmed compromised in Identity Protection (risk set to high; risk-based Conditional Access then applies).',
    mutating: true,
    destructive: true,
    riskBaseScore: 30,
    permissions: ['IdentityRiskyUser.ReadWrite.All'],
    resource: GUID,
    inputSchema: noParams,
    build: (r) => ({
      method: 'POST',
      path: 'identityProtection/riskyUsers/confirmCompromised',
      body: { userIds: [r] },
    }),
  },
  {
    name: 'entra.user.risk.dismiss',
    api: 'graph',
    description:
      "Dismiss a user's Identity Protection risk. Lowers protection for that user.",
    mutating: true,
    destructive: false,
    riskBaseScore: 30,
    permissions: ['IdentityRiskyUser.ReadWrite.All'],
    resource: GUID,
    inputSchema: noParams,
    build: (r) => ({
      method: 'POST',
      path: 'identityProtection/riskyUsers/dismiss',
      body: { userIds: [r] },
    }),
  },

  // ---- Defender for Endpoint: reads ----
  {
    name: 'defender.machine.get',
    api: 'defender',
    description: 'Read a Defender for Endpoint device by machine id.',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['Machine.Read.All'],
    resource: MACHINE,
    inputSchema: noParams,
    build: (r) => ({ method: 'GET', path: `machines/${seg(r)}` }),
  },
  {
    name: 'defender.machineaction.list',
    api: 'defender',
    description:
      'List response actions on a device (resource: machine id) and their status.',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['Machine.Read.All'],
    resource: MACHINE,
    inputSchema: topParams,
    build: (r, p) => ({
      method: 'GET',
      path: 'machineactions',
      query: { $filter: `machineId eq '${r}'`, ...topQuery(p) },
    }),
  },
  {
    name: 'defender.machineaction.get',
    api: 'defender',
    description: 'Read one response action (resource: machine action id).',
    mutating: false,
    destructive: false,
    riskBaseScore: 5,
    permissions: ['Machine.Read.All'],
    resource: GUID,
    inputSchema: noParams,
    build: (r) => ({ method: 'GET', path: `machineactions/${seg(r)}` }),
  },

  // ---- Defender for Endpoint: device response actions ----
  machineAction('defender.machine.isolate', 'isolate', {
    description:
      'Isolate a device from the network (Full or Selective). Reversible with defender.machine.unisolate.',
    destructive: true,
    riskBaseScore: 35,
    permissions: ['Machine.Isolate'],
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['comment'],
      properties: {
        comment,
        isolationType: { enum: ['Full', 'Selective'] },
      },
    },
    body: (p) => ({ IsolationType: p.isolationType ?? 'Full' }),
  }),
  machineAction('defender.machine.unisolate', 'unisolate', {
    description: 'Release a device from isolation.',
    destructive: false,
    riskBaseScore: 15,
    permissions: ['Machine.Isolate'],
  }),
  machineAction('defender.machine.antivirusScan', 'runAntiVirusScan', {
    description: 'Run a Microsoft Defender Antivirus scan (Quick or Full).',
    destructive: false,
    riskBaseScore: 10,
    permissions: ['Machine.Scan'],
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['comment'],
      properties: { comment, scanType: { enum: ['Quick', 'Full'] } },
    },
    body: (p) => ({ ScanType: p.scanType ?? 'Quick' }),
  }),
  machineAction(
    'defender.machine.collectInvestigationPackage',
    'collectInvestigationPackage',
    {
      description: 'Collect a forensic investigation package from a device.',
      destructive: false,
      riskBaseScore: 15,
      permissions: ['Machine.CollectForensics'],
    },
  ),
  machineAction(
    'defender.machine.stopAndQuarantineFile',
    'StopAndQuarantineFile',
    {
      description:
        'Stop a running file by SHA-1 on a device and quarantine it.',
      destructive: true,
      riskBaseScore: 35,
      permissions: ['Machine.StopAndQuarantine'],
      inputSchema: {
        type: 'object',
        additionalProperties: false,
        required: ['comment', 'sha1'],
        properties: {
          comment,
          sha1: { type: 'string', pattern: '^[0-9a-fA-F]{40}$' },
        },
      },
      body: (p) => ({ Sha1: p.sha1 }),
    },
  ),
];

const BY_NAME = new Map(MICROSOFT_ACTIONS.map((a) => [a.name, a]));

export function findMicrosoftAction(
  name: string,
): MicrosoftActionDef | undefined {
  return BY_NAME.get(name);
}
