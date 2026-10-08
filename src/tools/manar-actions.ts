/**
 * ADR-0009: the catalog of Manar's own built-in connector (`ToolProtocol
 * MANAR`, tool name `manar`). Pure data, no imports: task validation on the
 * decision path reads it.
 *
 * Restriction only. There is no release, deactivate, approve, grant or
 * policy action here, and task creation rejects any `manar` action that is
 * not in this list (`GrantableToolActionSchema`), so no agent can be given
 * one. Releasing a quarantine is a human API call (JWT + role).
 */

export const MANAR_TOOL = 'manar';
/**
 * The built-in connector is the `Tool` row named `manar` whose `baseEndpoint`
 * is this. Not a new `ToolProtocol` value: an API process still on the
 * previous Prisma client fails every tools query that returns a row with an
 * enum value it does not know (P2023), which a rolling upgrade or a shared
 * database would hit. Its protocol column says HTTP, and the HTTP adapter
 * can never call it (`manar:` is not an allowed outbound scheme).
 */
export const MANAR_BUILTIN_ENDPOINT = 'manar://builtin';

export function isManarBuiltin(tool: {
  name: string;
  baseEndpoint: string;
}): boolean {
  return (
    tool.name === MANAR_TOOL && tool.baseEndpoint === MANAR_BUILTIN_ENDPOINT
  );
}

export const MANAR_ACTIVITY_READ = 'manar.activity.read';
export const MANAR_AGENT_QUARANTINE = 'manar.agent.quarantine';

export interface ManarActionDefinition {
  name: string;
  description: string;
  riskBaseScore: number;
  mutating: boolean;
  destructive: boolean;
  inputSchema: Record<string, unknown>;
}

export const MANAR_ACTIONS: readonly ManarActionDefinition[] = [
  {
    name: MANAR_ACTIVITY_READ,
    description:
      'Read recent activity of agents in this tenant: decisions, approvals and tool invocations as metadata and counts. No parameters, payloads or secrets. Resource: any string (use "tenant").',
    riskBaseScore: 0,
    mutating: false,
    destructive: false,
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        windowSeconds: { type: 'integer', minimum: 10, maximum: 3600 },
        limit: { type: 'integer', minimum: 1, maximum: 1000 },
      },
    },
  },
  {
    // Mutating (it changes Manar state) but restriction only: it can stop an
    // agent, never start one. Base risk 0, so a task with riskCeiling >= 25
    // runs it without approval.
    name: MANAR_AGENT_QUARANTINE,
    description:
      'Quarantine an agent in this tenant: every action it requests is denied (agent_quarantined) until a human releases it. Resource: the agent id. Idempotent; a second call on an active quarantine may attach the explanation once.',
    riskBaseScore: 0,
    mutating: true,
    destructive: false,
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      required: ['reason'],
      properties: {
        reason: { type: 'string', minLength: 1, maxLength: 500 },
        detector: { type: 'string', maxLength: 64 },
        evidence: {
          type: 'array',
          maxItems: 50,
          items: { type: 'string', maxLength: 128 },
        },
        explanation: {
          type: 'object',
          additionalProperties: false,
          required: ['en', 'ar'],
          properties: {
            en: { type: 'string', minLength: 1, maxLength: 1500 },
            ar: { type: 'string', minLength: 1, maxLength: 1500 },
          },
        },
      },
    },
  },
];

export const MANAR_ACTION_NAMES: ReadonlySet<string> = new Set(
  MANAR_ACTIONS.map((a) => a.name),
);
