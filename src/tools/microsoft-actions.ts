import { randomBytes } from 'node:crypto';

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
  method: 'GET' | 'POST' | 'PATCH';
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
  build(resource: string, params: Record<string, unknown>): MicrosoftRequest;
}

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
 * A temporary password Manar sets and never returns, logs or stores: the
 * point of the reset is to lock the current holder of the password out.
 * The user gets back in through self-service reset or the helpdesk. The
 * suffix guarantees Entra's complexity rule (3 of 4 character classes).
 */
function lockoutPassword(): string {
  return `${randomBytes(24).toString('base64url')}Aa1!`;
}

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
      'Replace the password with a random one Manar never reveals and require a change at next sign-in. Locks the current password holder out; the user recovers via self-service reset or the helpdesk.',
    mutating: true,
    destructive: true,
    riskBaseScore: 40,
    permissions: ['User-PasswordProfile.ReadWrite.All'],
    resource: USER,
    inputSchema: noParams,
    build: (r) => ({
      method: 'PATCH',
      path: `users/${seg(r)}`,
      body: {
        passwordProfile: {
          password: lockoutPassword(),
          forceChangePasswordNextSignIn: true,
        },
      },
    }),
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
