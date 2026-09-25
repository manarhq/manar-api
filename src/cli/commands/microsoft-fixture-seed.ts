import type { PrismaClient as TenantPrismaClient } from '../../generated/tenant-client/client';
import type { Prisma } from '../../generated/tenant-client/client';
import { MICROSOFT_ACTIONS } from '../../tools/microsoft-actions';

/**
 * Registers the Microsoft catalog (ADR-0004) for one tenant, pointed at the
 * DEMO FIXTURE in `packages/demo-soc-tools/src/microsoft/`. Used by
 * `pnpm manar demo:seed --microsoft-fixture-url` and by
 * `test/microsoft-connector.e2e-spec.ts`. Tool and action names are the
 * ones a live tenant will use, so policies and task grants carry over; only
 * `baseEndpoint`, `metadata` and the OpenBao secret change.
 */

export const MICROSOFT_GRAPH_TOOL = 'microsoft-graph';
export const MICROSOFT_DEFENDER_TOOL = 'microsoft-defender';

/** The fixture's dev-only app registration (mirrors `FIXTURE_DEFAULTS` in the fixture package, which the build cannot import). */
export const MICROSOFT_FIXTURE_APP = {
  azureTenantId: '00000000-0000-4000-8000-00000000f1c5',
  clientId: '11111111-2222-4333-8444-555555555555',
  clientSecret: 'manar-dev-microsoft-fixture-secret',
} as const;

/** The fixture's seeded identities (mirrors the fixture's `seed-data.ts`). */
export const MICROSOFT_FIXTURE_IDS = {
  userId: '7f3c2a1e-4b5d-4e6f-8a9b-0c1d2e3f4a5b',
  machineId: '4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70',
  incidentId: '4201',
} as const;

export const MICROSOFT_FIXTURE_KV_PATH = 'tools/microsoft-fixture';

/** The fixture's two alerts on incident 4201 (mirrors the fixture's `seed-data.ts`). */
export const MICROSOFT_FIXTURE_ALERT_IDS = [
  'da-fixture-0001',
  'da-fixture-0002',
] as const;

/**
 * Grants for the LLM SOC agent's task (ADR-0002): read the incident, its
 * alerts, the user (profile, sign-ins, risk) and the device; disable the user
 * and isolate the device, both APPROVAL_REQUIRED under
 * `microsoftPolicyContent()`.
 *
 * No list actions: grants are the cross-join of actions and selectors per
 * tool, and one more selector (`all`) would push task creation past
 * OpenFGA's 100-tuple write limit. The incident read returns its alerts.
 */
export function socAgentTaskGrants() {
  const { userId, machineId, incidentId } = MICROSOFT_FIXTURE_IDS;
  return {
    allowedToolActions: [
      ...[
        'security.incident.get',
        'security.alert.get',
        'entra.user.get',
        'entra.user.signins.list',
        'entra.user.risk.get',
        'entra.user.disable',
      ].map((actionId) => ({ toolId: MICROSOFT_GRAPH_TOOL, actionId })),
      ...['defender.machine.get', 'defender.machine.isolate'].map(
        (actionId) => ({ toolId: MICROSOFT_DEFENDER_TOOL, actionId }),
      ),
    ],
    allowedResourceSelectors: [
      ...[incidentId, userId, ...MICROSOFT_FIXTURE_ALERT_IDS].map(
        (pattern) => ({ toolId: MICROSOFT_GRAPH_TOOL, pattern }),
      ),
      { toolId: MICROSOFT_DEFENDER_TOOL, pattern: machineId },
    ],
    forbiddenActions: [],
  };
}

export async function ensureMicrosoftFixtureTools(
  tenantClient: TenantPrismaClient,
  input: { fixtureBaseUrl: string; kvPath: string },
): Promise<void> {
  const base = `${input.fixtureBaseUrl.replace(/\/+$/, '')}/microsoft`;
  const tools = [
    {
      name: MICROSOFT_GRAPH_TOOL,
      api: 'graph',
      type: 'IAM',
      path: '/graph/v1.0',
    },
    {
      name: MICROSOFT_DEFENDER_TOOL,
      api: 'defender',
      type: 'EDR',
      path: '/defender/api',
    },
  ] as const;

  for (const def of tools) {
    const data = {
      type: def.type,
      vendor: 'Microsoft',
      description: `Microsoft ${def.api === 'graph' ? 'Graph' : 'Defender for Endpoint'} connector pointed at the local DEMO FIXTURE, not a live tenant.`,
      baseEndpoint: `${base}${def.path}`,
      protocol: 'MICROSOFT' as const,
      credentialReference: { provider: 'OPENBAO', reference: input.kvPath },
      metadata: {
        api: def.api,
        azureTenantId: MICROSOFT_FIXTURE_APP.azureTenantId,
        clientId: MICROSOFT_FIXTURE_APP.clientId,
        authorityUrl: `${base}/login`,
        dataOrigin: 'DEMO_FIXTURE',
      },
    };
    const tool = await tenantClient.tool.upsert({
      where: { name: def.name },
      create: { name: def.name, ...data },
      update: data,
    });

    for (const action of MICROSOFT_ACTIONS.filter((a) => a.api === def.api)) {
      const row = {
        description: action.description,
        riskBaseScore: action.riskBaseScore,
        mutating: action.mutating,
        destructive: action.destructive,
        inputSchema: action.inputSchema as Prisma.InputJsonObject,
      };
      await tenantClient.toolAction.upsert({
        where: { toolId_name: { toolId: tool.id, name: action.name } },
        create: { toolId: tool.id, name: action.name, ...row },
        update: row,
      });
    }
  }
}

/** Every Microsoft mutation needs a human approval; reads are allowed. Generated from the catalog, so a new action cannot slip through unlisted. */
export function microsoftPolicyContent() {
  const toolOf = (api: string) =>
    api === 'graph' ? MICROSOFT_GRAPH_TOOL : MICROSOFT_DEFENDER_TOOL;
  return {
    rules: [
      ...MICROSOFT_ACTIONS.filter((a) => a.mutating).map((a) => ({
        name: `${a.name} requires approval`,
        toolId: toolOf(a.api),
        actionId: a.name,
        resourcePattern: '*',
        effect: 'APPROVAL_REQUIRED' as const,
        riskWeight: a.destructive ? 40 : 20,
        description: a.description,
      })),
      ...MICROSOFT_ACTIONS.filter((a) => !a.mutating).map((a) => ({
        name: `${a.name} is a read`,
        toolId: toolOf(a.api),
        actionId: a.name,
        effect: 'ALLOW' as const,
      })),
    ],
  };
}
