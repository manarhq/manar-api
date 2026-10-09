import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Command, CommandRunner, Option } from 'nest-commander';
import { FileIdentityStore, ManarAgent } from '@manar/sdk-node';
import { AppConfig } from '../../config/env.validation';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { TenantDatabaseManager } from '../../database/tenant-database-manager.service';
import { TenantProvisioningService } from '../../keycloak/tenant-provisioning.service';
import { KeycloakAdminClient } from '../../keycloak/keycloak-admin.client';
import { OpenBaoKvClient } from '../../openbao/openbao-kv.client';
import {
  ensureMicrosoftFixtureTools,
  MICROSOFT_DEFENDER_TOOL,
  MICROSOFT_FIXTURE_APP,
  MICROSOFT_FIXTURE_IDS,
  MICROSOFT_FIXTURE_KV_PATH,
  MICROSOFT_GRAPH_TOOL,
  microsoftPolicyContent,
  socAgentTaskGrants,
} from './microsoft-fixture-seed';

interface DemoSeedOptions {
  apiEndpoint: string;
  demoToolsBaseUrl: string;
  demoToolsApiKey: string;
  /** Base URL of demo-soc-tools serving the Microsoft DEMO FIXTURE; empty skips the Microsoft catalog. */
  microsoftFixtureUrl: string;
}

/** Fixed, deterministic identifiers — never randomized — so re-running this command finds and reuses everything a prior run already created (Section 85: "idempotently provisions"). */
const TENANT_SLUG =
  process.env.MANAR_SEED_TENANT_SLUG ?? 'vax-security-ops-demo';
const TENANT_NAME =
  process.env.MANAR_SEED_TENANT_NAME ?? 'VAX Security Operations Demo';

/** Dev-only, documented in docs/demo.md — never used outside a local/demo deployment. */
const DEMO_USER_PASSWORD = 'Passw0rd!Demo2026';

const DEMO_USERS = [
  {
    username: 'demo-owner',
    email: 'owner@vax-demo.local',
    displayName: 'Dana Owner',
    role: 'TENANT_OWNER',
  },
  {
    username: 'demo-soc-operator',
    email: 'soc-operator@vax-demo.local',
    displayName: 'Sam Operator',
    role: 'SOC_OPERATOR',
  },
  {
    username: 'demo-approver',
    email: 'approver@vax-demo.local',
    displayName: 'Amir Approver',
    role: 'APPROVER',
  },
  {
    username: 'demo-auditor',
    email: 'auditor@vax-demo.local',
    displayName: 'Aisha Auditor',
    role: 'AUDITOR',
  },
] as const;

/** Enrolls itself; see DEMO_AGENTS. */
const SOC_LLM_AGENT_SLUG = 'manar-soc-agent';

const DEMO_AGENTS = [
  { slug: 'soc-response-agent', displayName: 'SOC Response Agent' },
  { slug: 'threat-hunting-agent', displayName: 'Threat Hunting Agent' },
  { slug: 'compromised-demo-agent', displayName: 'Compromised Demo Agent' },
  // The Python LLM SOC agent (manar-agents). Created here but never enrolled
  // by this command: the agent generates its own key in its pod and enrolls
  // with a one-time token (docs/adr/ADR-0002-llm-proxy.md, "Agent contract").
  { slug: SOC_LLM_AGENT_SLUG, displayName: 'Manar SOC Agent (LLM)' },
] as const;

/** The exact `WS-042`/`INC-2026-0042` demo host/incident seeded by `packages/demo-soc-tools` (Phase 7a) — never renamed casually, see that package's own seed-data.ts doc comment. */
const DEMO_HOST_ID = 'WS-042';

interface ToolActionDef {
  name: string;
  riskBaseScore: number;
  mutating: boolean;
  destructive: boolean;
  /** Phase 15a (Section 53) — omitted means the schema default (`INTERNAL`) applies; only `iam.disable-user` sets this explicitly (`RESTRICTED`) below, so "Restricted Classification Approval Policy" has a real demo action to match against. */
  classification?: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
}

interface ToolDef {
  name: string;
  type: string;
  actions: ToolActionDef[];
}

/** Covers every SIEM/EDR/IAM/Firewall action Section 36/37 lists — including IAM/firewall actions this task's own grant deliberately never includes, so the Tool Registry/Risk Engine at least recognize them as real, registered actions. */
const DEMO_TOOLS: ToolDef[] = [
  {
    name: 'siem',
    type: 'SIEM',
    actions: [
      {
        name: 'search-events',
        riskBaseScore: 5,
        mutating: false,
        destructive: false,
      },
      {
        name: 'fetch-incident',
        riskBaseScore: 5,
        mutating: false,
        destructive: false,
      },
    ],
  },
  {
    name: 'edr',
    type: 'EDR',
    actions: [
      {
        name: 'get-host',
        riskBaseScore: 5,
        mutating: false,
        destructive: false,
      },
      {
        name: 'isolate-host',
        riskBaseScore: 15,
        mutating: true,
        destructive: false,
      },
    ],
  },
  {
    name: 'iam',
    type: 'IAM',
    actions: [
      {
        name: 'get-user',
        riskBaseScore: 5,
        mutating: false,
        destructive: false,
      },
      {
        name: 'disable-user',
        riskBaseScore: 40,
        mutating: true,
        destructive: true,
        // Phase 15a (Section 53) — disabling a user account touches
        // sensitive identity data; classified RESTRICTED so "Restricted
        // Classification Approval Policy" below has a real demo action to
        // match. This task's own grant never includes any `iam` action at
        // all (see DEMO_POLICIES's own doc comment), so this is
        // defense-in-depth, exercised directly by this phase's tests
        // rather than through the demo task itself.
        classification: 'RESTRICTED',
      },
    ],
  },
  {
    name: 'firewall',
    type: 'FIREWALL',
    actions: [
      {
        name: 'lookup-ip',
        riskBaseScore: 5,
        mutating: false,
        destructive: false,
      },
      {
        name: 'block-ip',
        riskBaseScore: 20,
        mutating: true,
        destructive: false,
      },
      {
        name: 'unblock-ip',
        riskBaseScore: 15,
        mutating: true,
        destructive: false,
      },
    ],
  },
];

const OPENBAO_DEMO_TOOLS_KV_PATH = 'tools/demo-soc-tools';

interface PolicyDef {
  name: string;
  description: string;
  content: {
    rules: Array<{
      name: string;
      toolId: string;
      actionId: string;
      resourcePattern?: string;
      effect: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
      riskWeight?: number;
      riskFloor?: number;
      description?: string;
      /** Phase 15a (Section 53) — see `PolicyRuleSchema.resourceClassification`'s doc comment. */
      resourceClassification?:
        'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
    }>;
  };
}

/**
 * Four real, published policies (Phase 6's actual rule schema) shaping
 * this demo's intended allow/deny/approval story: SIEM reads ALLOW, EDR
 * isolation APPROVAL_REQUIRED, IAM mutations DENY (defense in depth on top
 * of — not a substitute for — the fact that this task's own grant never
 * includes any `iam`/`firewall` action at all, so those are already
 * denied at the OpenFGA task-scope step before any policy is even
 * consulted; see docs/authorization-model.md/docs/policy-model.md).
 *
 * "No Secret Exfiltration Policy" is a real published policy using this
 * same schema — but that schema only ever matches on
 * `{toolId, actionId, resourcePattern}` triples, never request/response
 * *content* (content-based detection is Section 73/Phase 10b's DLP job,
 * already wired independently via `AiAdvisoryClient.analyzeDlp` — see
 * docs/ai-security-model.md). So this policy is a standing, org-wide
 * guardrail against a plausible future `credential-store`-shaped tool
 * this org has not decided to trust any agent with at all, rather than a
 * content scanner PolicyEngine was never built to be. It does not match
 * anything this specific demo scenario invokes.
 */
const DEMO_POLICIES: PolicyDef[] = [
  {
    name: 'SOC Read Policy',
    description:
      'SOC tooling may read SIEM events/incidents and EDR host state freely.',
    content: {
      rules: [
        {
          name: 'Allow SIEM reads',
          toolId: 'siem',
          actionId: '*',
          effect: 'ALLOW',
        },
        {
          name: 'Allow EDR host reads',
          toolId: 'edr',
          actionId: 'get-host',
          effect: 'ALLOW',
        },
      ],
    },
  },
  {
    name: 'Endpoint Isolation Approval Policy',
    description:
      'Isolating a host is disruptive and hard to reverse quickly — always route through human approval, even for a task otherwise granted edr.isolate-host.',
    content: {
      rules: [
        {
          name: 'Endpoint isolation always requires approval',
          toolId: 'edr',
          actionId: 'isolate-host',
          resourcePattern: '*',
          effect: 'APPROVAL_REQUIRED',
          riskWeight: 55,
          riskFloor: 60,
          description:
            'Isolating a host is disruptive and hard to reverse quickly.',
        },
      ],
    },
  },
  {
    name: 'IAM Restriction Policy',
    description:
      'Autonomous agents may never mutate IAM state — reads are fine.',
    content: {
      rules: [
        {
          name: 'Allow IAM reads',
          toolId: 'iam',
          actionId: 'get-user',
          effect: 'ALLOW',
        },
        {
          name: 'Deny all IAM mutations',
          toolId: 'iam',
          actionId: '*',
          effect: 'DENY',
          riskWeight: 80,
          description:
            'Autonomous agents may never mutate IAM state, full stop.',
        },
      ],
    },
  },
  {
    // Phase 15a (Section 53): a real, worked example of `resourceClassification`
    // matching — demonstrates that a policy CAN express "require approval
    // for RESTRICTED-classified actions" (nothing is hardcoded to
    // auto-deny; see docs/data-classification.md). Matches
    // `iam.disable-user`, the one demo ToolAction seeded with
    // `classification: 'RESTRICTED'` — this task's own grant never
    // includes any `iam` action, so this rule is exercised directly by
    // this phase's own tests rather than through the demo task/agent
    // flow.
    name: 'Restricted Classification Approval Policy',
    description:
      'Any action against a RESTRICTED-classified resource always requires human approval, regardless of which tool/action it is or what a task was otherwise granted.',
    content: {
      rules: [
        {
          name: 'Require approval for RESTRICTED-classified actions',
          toolId: '*',
          actionId: '*',
          effect: 'APPROVAL_REQUIRED',
          resourceClassification: 'RESTRICTED',
          riskWeight: 50,
          riskFloor: 65,
          description:
            'RESTRICTED data warrants a human in the loop before any agent acts on it, independent of the specific tool/action involved.',
        },
      ],
    },
  },
  {
    name: 'No Secret Exfiltration Policy',
    description:
      'Standing org-wide guardrail: no autonomous agent may interact with the credential-store tool, full stop.',
    content: {
      rules: [
        {
          name: 'Deny any interaction with the credential-store tool',
          toolId: 'credential-store',
          actionId: '*',
          effect: 'DENY',
          riskWeight: 90,
          description:
            'No autonomous agent may read or export secrets/credentials directly.',
        },
      ],
    },
  },
];

const DEMO_TASK_NAME = 'SOC Incident Response — INC-2026-0042';
const MICROSOFT_TASK_NAME =
  'Microsoft Incident Response — incident 4201 (DEMO FIXTURE)';
const SOC_LLM_TASK_NAME =
  'Manar SOC agent — triage incident 4201 (DEMO FIXTURE)';

/**
 * Where this command hands the demo tenant's credentials off to
 * `scripts/demo-agent.ts` (gitignored — see `.gitignore`). The Keycloak
 * client secret has no HTTP endpoint that returns it, by design (Section
 * 11 — it's provisioning-time-only control-DB state, never something any
 * application endpoint echoes back); this file is the realistic
 * equivalent of an operator handing a freshly-provisioned confidential
 * client's secret to whichever tooling needs it next, the same way a real
 * deployment's provisioning step would. `scripts/demo-agent.ts` then acts
 * purely as an ordinary API/SDK client using credentials it was given —
 * it never touches Postgres/Keycloak admin APIs directly.
 */
const CREDENTIALS_FILE_PATH = '.manar-demo/tenant-credentials.json';

interface DemoTenantCredentials {
  tenantId: string;
  tenantSlug: string;
  keycloakRealm: string;
  keycloakClientId: string;
  keycloakClientSecret: string;
  userPassword: string;
  users: Record<string, string>;
  agents: Record<string, { id: string; slug: string }>;
  taskId: string;
  /** Present only when seeded with `--microsoft-fixture-url`. */
  microsoftTaskId?: string;
  /** The Python LLM SOC agent's task; present only with `--microsoft-fixture-url`. */
  socLlmAgent?: { agentId: string; agentSlug: string; taskId: string };
}

interface HttpJsonOptions {
  method: 'GET' | 'POST';
  token?: string;
  body?: unknown;
}

interface AgentSummaryBody {
  id: string;
  slug: string;
  status: string;
}

/**
 * `pnpm manar demo:seed` (Section 85) — idempotently provisions the "VAX
 * Security Operations Demo" tenant end to end: a real tenant (real
 * Keycloak realm/tenant DB), four real Keycloak users with real roles,
 * three real enrolled agents (real certificates), `Tool`/`ToolAction`
 * rows pointing at the real running `packages/demo-soc-tools` service,
 * four real published policies, and a task granting "SOC Response Agent"
 * exactly the SIEM read + EDR scope Section 37's example describes.
 *
 * Architecture note: tenant provisioning and Keycloak user/role
 * management have no HTTP surface at all (Section 11 — CLI-only), so
 * those two steps call `TenantProvisioningService`/`KeycloakAdminClient`
 * directly, exactly like `tenant:create` (`src/cli/commands/tenant-create.command.ts`).
 * Everything else this command creates (agents, enrollment, policies,
 * tasks) *does* have a real, documented human-facing HTTP API — so this
 * command drives that real API over HTTP with a real Keycloak-issued JWT
 * for the seeded tenant owner, the same way any other legitimate API
 * client (a human operator, `curl`, a provisioning script) would, rather
 * than reaching around it via direct service injection. This requires
 * `manar-api`'s human-facing HTTP server (`pnpm start:dev`) to already be
 * running and reachable at `--api-endpoint` (default
 * `http://localhost:3000`) — see docs/demo.md. Agent enrollment
 * specifically uses the real `@manar/sdk-node` `ManarAgent.enroll()` —
 * Section 85's explicit "run through the real enrollment flow, don't
 * hand-insert Agent rows" requirement. `Tool`/`ToolAction` rows are
 * written directly against the tenant database — there is no
 * human-facing registration API for those this phase either (see
 * docs/tool-gateway.md's "out of scope" note; `test/tool-gateway-demo-integration.e2e-spec.ts`
 * does the same thing for the same reason).
 */
@Command({
  name: 'demo:seed',
  description:
    'Idempotently provision the "VAX Security Operations Demo" tenant, users, agents, tools, policies, and task (Phase 13)',
})
export class DemoSeedCommand extends CommandRunner {
  private readonly logger = new Logger(DemoSeedCommand.name);
  private readonly keycloakBaseUrl: string;

  constructor(
    private readonly tenantProvisioningService: TenantProvisioningService,
    private readonly keycloakAdminClient: KeycloakAdminClient,
    private readonly control: ControlPrismaService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly openBaoKvClient: OpenBaoKvClient,
    configService: ConfigService<AppConfig, true>,
  ) {
    super();
    this.keycloakBaseUrl = configService.get('KEYCLOAK_BASE_URL', {
      infer: true,
    });
  }

  async run(_passedParams: string[], options: DemoSeedOptions): Promise<void> {
    this.logger.log(`Seeding demo tenant "${TENANT_SLUG}" ...`);

    const tenant = await this.ensureTenant();
    if (!tenant.keycloakRealm || !tenant.keycloakClientId) {
      throw new Error(
        `Tenant "${TENANT_SLUG}" has no Keycloak realm/client — Keycloak provisioning must have failed on an earlier run; re-run "pnpm manar demo:seed" once Keycloak is reachable`,
      );
    }
    const realm = tenant.keycloakRealm;

    const clientSecretRef = await this.control.secretReference.findFirstOrThrow(
      { where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' } },
    );

    const userIds = await this.ensureUsers(realm);
    this.logger.log(`Ensured ${Object.keys(userIds).length} demo users`);

    const ownerToken = await this.getUserToken({
      realm,
      clientId: tenant.keycloakClientId,
      clientSecret: clientSecretRef.reference,
      username: 'demo-owner',
      password: DEMO_USER_PASSWORD,
    });

    const agents = await this.ensureAgents(options.apiEndpoint, ownerToken);
    this.logger.log(
      `Ensured ${agents.size} demo agents: ${[...agents.values()].map((a) => `${a.slug} (${a.status})`).join(', ')}`,
    );

    await this.ensureAgentsEnrolled(options.apiEndpoint, ownerToken, agents);

    await this.writeDemoToolsCredential(options.demoToolsApiKey);
    await this.ensureToolsAndActions(tenant.id, options.demoToolsBaseUrl);
    this.logger.log(`Ensured ${DEMO_TOOLS.length} demo tools`);

    await this.ensurePolicies(options.apiEndpoint, ownerToken, DEMO_POLICIES);
    this.logger.log(`Ensured ${DEMO_POLICIES.length} demo policies`);

    const socResponseAgent = agents.get('soc-response-agent');
    if (!socResponseAgent) {
      throw new Error(
        'SOC Response Agent was not created — cannot create demo task',
      );
    }
    const task = await this.ensureTask(
      tenant.id,
      options.apiEndpoint,
      ownerToken,
      socResponseAgent.id,
    );

    const microsoftTask = options.microsoftFixtureUrl
      ? await this.ensureMicrosoftFixture(
          tenant.id,
          options,
          ownerToken,
          socResponseAgent.id,
        )
      : undefined;

    const socLlmAgent = agents.get(SOC_LLM_AGENT_SLUG);
    const socLlmTask =
      options.microsoftFixtureUrl && socLlmAgent
        ? await this.ensureSocLlmTask(
            tenant.id,
            options.apiEndpoint,
            ownerToken,
            socLlmAgent.id,
          )
        : undefined;

    await this.writeCredentialsFile({
      tenantId: tenant.id,
      tenantSlug: TENANT_SLUG,
      keycloakRealm: realm,
      keycloakClientId: tenant.keycloakClientId,
      keycloakClientSecret: clientSecretRef.reference,
      userPassword: DEMO_USER_PASSWORD,
      users: Object.fromEntries(DEMO_USERS.map((u) => [u.role, u.username])),
      agents: Object.fromEntries(
        [...agents.values()].map((a) => [a.slug, { id: a.id, slug: a.slug }]),
      ),
      taskId: task.id,
      ...(microsoftTask ? { microsoftTaskId: microsoftTask.id } : {}),
      ...(socLlmAgent && socLlmTask
        ? {
            socLlmAgent: {
              agentId: socLlmAgent.id,
              agentSlug: SOC_LLM_AGENT_SLUG,
              taskId: socLlmTask.id,
            },
          }
        : {}),
    });

    this.logger.log('');
    this.logger.log('=== Demo seed complete ===');
    this.logger.log(
      `Tenant: ${TENANT_NAME} (slug=${TENANT_SLUG}, id=${tenant.id})`,
    );
    this.logger.log(`Keycloak realm: ${realm}`);
    this.logger.log(`Demo user password (all 4 users): ${DEMO_USER_PASSWORD}`);
    for (const user of DEMO_USERS) {
      this.logger.log(`  - ${user.username} (${user.role})`);
    }
    for (const agent of agents.values()) {
      this.logger.log(
        `Agent: ${agent.displayName} (slug=${agent.slug}, id=${agent.id}, status=${agent.status})`,
      );
    }
    this.logger.log(`Task: ${DEMO_TASK_NAME} (id=${task.id})`);
    if (socLlmTask) {
      this.logger.log(
        `LLM SOC agent task: ${SOC_LLM_TASK_NAME} (id=${socLlmTask.id}); enroll the agent with a token from POST /agents/${socLlmAgent?.id}/enrollment-tokens`,
      );
    }
    this.logger.log(`Wrote credentials handoff file: ${CREDENTIALS_FILE_PATH}`);
    this.logger.log(
      'See docs/demo.md for how to run the demo agent script next.',
    );
    process.exitCode = 0;
  }

  private async writeCredentialsFile(
    credentials: DemoTenantCredentials,
  ): Promise<void> {
    await mkdir(dirname(CREDENTIALS_FILE_PATH), { recursive: true });
    await writeFile(
      CREDENTIALS_FILE_PATH,
      JSON.stringify(credentials, null, 2),
      { mode: 0o600 },
    );
  }

  // ---- Tenant ----

  private async ensureTenant() {
    const existing = await this.control.tenant.findUnique({
      where: { slug: TENANT_SLUG },
    });
    if (existing) {
      this.logger.log(
        `Tenant "${TENANT_SLUG}" already exists (id=${existing.id}) — reusing it`,
      );
      return existing;
    }

    const provisioned = await this.tenantProvisioningService.provisionTenant({
      slug: TENANT_SLUG,
      name: TENANT_NAME,
    });
    this.logger.log(
      `Provisioned tenant "${TENANT_SLUG}" (id=${provisioned.id})`,
    );
    return provisioned;
  }

  // ---- Keycloak users ----

  private async ensureUsers(realm: string): Promise<Record<string, string>> {
    const userIds: Record<string, string> = {};
    for (const user of DEMO_USERS) {
      const existing = await this.keycloakAdminClient.findUserByUsername(
        realm,
        user.username,
      );
      let userId: string;
      if (existing) {
        userId = existing.id;
      } else {
        const [firstName, ...rest] = user.displayName.split(' ');
        userId = await this.keycloakAdminClient.createUser(realm, {
          username: user.username,
          email: user.email,
          password: DEMO_USER_PASSWORD,
          firstName: firstName ?? user.displayName,
          lastName: rest.join(' ') || 'Demo',
        });
        this.logger.log(`Created Keycloak user "${user.username}"`);
      }
      await this.keycloakAdminClient.assignRealmRole(realm, userId, user.role);
      userIds[user.username] = userId;
    }
    return userIds;
  }

  private async getUserToken(input: {
    realm: string;
    clientId: string;
    clientSecret: string;
    username: string;
    password: string;
  }): Promise<string> {
    const response = await fetch(
      `${this.keycloakBaseUrl}/realms/${encodeURIComponent(input.realm)}/protocol/openid-connect/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'password',
          client_id: input.clientId,
          client_secret: input.clientSecret,
          username: input.username,
          password: input.password,
          scope: 'openid',
        }),
      },
    );
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(
        `Failed to obtain a token for "${input.username}": HTTP ${response.status}${text ? `: ${text}` : ''}`,
      );
    }
    const body = (await response.json()) as { access_token: string };
    return body.access_token;
  }

  // ---- HTTP client for manar-api's real human-facing API ----

  private async httpJson<T>(
    apiEndpoint: string,
    path: string,
    options: HttpJsonOptions,
  ): Promise<T> {
    const response = await fetch(new URL(path, apiEndpoint), {
      method: options.method,
      headers: {
        ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(
        `${options.method} ${path} against manar-api (${apiEndpoint}) failed: HTTP ${response.status}${text ? `: ${text}` : ''} -- is "pnpm start:dev" running? See docs/demo.md.`,
      );
    }
    return (await response.json()) as T;
  }

  // ---- Agents ----

  private async ensureAgents(
    apiEndpoint: string,
    ownerToken: string,
  ): Promise<
    Map<
      string,
      { id: string; slug: string; displayName: string; status: string }
    >
  > {
    const existingList = await this.httpJson<{ items: AgentSummaryBody[] }>(
      apiEndpoint,
      '/agents?limit=100',
      { method: 'GET', token: ownerToken },
    );

    const result = new Map<
      string,
      { id: string; slug: string; displayName: string; status: string }
    >();
    for (const def of DEMO_AGENTS) {
      const existing = existingList.items.find((a) => a.slug === def.slug);
      if (existing) {
        result.set(def.slug, {
          id: existing.id,
          slug: def.slug,
          displayName: def.displayName,
          status: existing.status,
        });
        continue;
      }

      const created = await this.httpJson<{
        id: string;
        slug: string;
        status: string;
      }>(apiEndpoint, '/agents', {
        method: 'POST',
        token: ownerToken,
        body: { slug: def.slug, displayName: def.displayName },
      });
      this.logger.log(`Created agent "${def.displayName}" (id=${created.id})`);
      result.set(def.slug, {
        id: created.id,
        slug: def.slug,
        displayName: def.displayName,
        status: created.status,
      });
    }
    return result;
  }

  /**
   * Fully enrolls (real enrollment token -> real cert, via the real SDK)
   * every demo agent still `PENDING_ENROLLMENT` — Section 85's "real
   * enrolled agents, real certificates" requirement. The demo agent
   * script (`scripts/demo-agent.ts`) performs its *own*, independent
   * fresh enrollment for "SOC Response Agent" as its own first live step
   * regardless of what this command already did — re-enrolling an
   * already-`ACTIVE` agent with a fresh token is legal
   * (`CertificateAuthorityService` never gates on current `Agent.status`)
   * and produces a second, independently valid certificate, so both are
   * simultaneously true: this command's seed data is "real enrolled
   * agents" end to end, and the demo script still gets to demonstrate a
   * live enrollment of its own.
   */
  private async ensureAgentsEnrolled(
    apiEndpoint: string,
    ownerToken: string,
    agents: Map<
      string,
      { id: string; slug: string; displayName: string; status: string }
    >,
  ): Promise<void> {
    for (const agent of agents.values()) {
      if (
        agent.status !== 'PENDING_ENROLLMENT' ||
        agent.slug === SOC_LLM_AGENT_SLUG
      ) {
        continue;
      }
      const tokenResponse = await this.httpJson<{ token: string }>(
        apiEndpoint,
        `/agents/${agent.id}/enrollment-tokens`,
        { method: 'POST', token: ownerToken },
      );

      const identityStore = new FileIdentityStore(
        `.manar-demo/identities/${agent.slug}.identity`,
        'manar-demo-seed-identity-not-for-production',
      );
      const manar = new ManarAgent({
        endpoint: apiEndpoint,
        identityStore,
      });
      await manar.enroll(tokenResponse.token);
      agent.status = 'ACTIVE';
      this.logger.log(
        `Enrolled agent "${agent.displayName}" — real certificate issued`,
      );
    }
  }

  // ---- Tools / ToolActions (direct tenant-DB writes — no HTTP registration API exists this phase) ----

  private async writeDemoToolsCredential(apiKey: string): Promise<void> {
    await this.openBaoKvClient.writeSecret(OPENBAO_DEMO_TOOLS_KV_PATH, {
      value: apiKey,
    });
  }

  private async ensureToolsAndActions(
    tenantId: string,
    demoToolsBaseUrl: string,
  ): Promise<void> {
    const tenantClient = await this.tenantDatabaseManager.getClient(tenantId);

    for (const toolDef of DEMO_TOOLS) {
      let tool = await tenantClient.tool.findFirst({
        where: { name: toolDef.name },
      });
      if (!tool) {
        tool = await tenantClient.tool.create({
          data: {
            name: toolDef.name,
            type: toolDef.type,
            baseEndpoint: `${demoToolsBaseUrl.replace(/\/+$/, '')}/v1/${toolDef.name}/`,
            protocol: 'HTTP',
            credentialReference: {
              provider: 'OPENBAO',
              reference: OPENBAO_DEMO_TOOLS_KV_PATH,
            },
            enabled: true,
          },
        });
        this.logger.log(`Registered Tool "${toolDef.name}"`);
      }

      for (const actionDef of toolDef.actions) {
        const existingAction = await tenantClient.toolAction.findFirst({
          where: { toolId: tool.id, name: actionDef.name },
        });
        if (existingAction) continue;

        await tenantClient.toolAction.create({
          data: {
            toolId: tool.id,
            name: actionDef.name,
            riskBaseScore: actionDef.riskBaseScore,
            mutating: actionDef.mutating,
            destructive: actionDef.destructive,
            inputSchema: { type: 'object' },
            ...(actionDef.classification
              ? { classification: actionDef.classification }
              : {}),
          },
        });
        this.logger.log(
          `Registered ToolAction "${toolDef.name}.${actionDef.name}"`,
        );
      }
    }
  }

  // ---- Policies ----

  private async ensurePolicies(
    apiEndpoint: string,
    ownerToken: string,
    policies: PolicyDef[],
  ): Promise<void> {
    for (const policyDef of policies) {
      const existingPolicies = await this.httpJson<{
        items: Array<{ id: string; name: string }>;
      }>(apiEndpoint, '/policies?limit=100', {
        method: 'GET',
        token: ownerToken,
      });

      if (existingPolicies.items.some((p) => p.name === policyDef.name)) {
        continue;
      }

      const created = await this.httpJson<{
        id: string;
        latestVersion: { id: string };
      }>(apiEndpoint, '/policies', {
        method: 'POST',
        token: ownerToken,
        body: {
          name: policyDef.name,
          description: policyDef.description,
          content: policyDef.content,
          reason: 'Phase 13 demo seed',
        },
      });

      await this.httpJson(
        apiEndpoint,
        `/policies/${created.id}/versions/${created.latestVersion.id}/publish`,
        { method: 'POST', token: ownerToken },
      );
      this.logger.log(`Created and published policy "${policyDef.name}"`);
    }
  }

  // ---- Task ----

  private async ensureTask(
    tenantId: string,
    apiEndpoint: string,
    ownerToken: string,
    socResponseAgentId: string,
  ): Promise<{ id: string }> {
    const tenantClient = await this.tenantDatabaseManager.getClient(tenantId);
    const existing = await tenantClient.task.findFirst({
      where: { name: DEMO_TASK_NAME },
    });
    if (existing) {
      return existing;
    }

    const created = await this.httpJson<{ id: string }>(apiEndpoint, '/tasks', {
      method: 'POST',
      token: ownerToken,
      body: {
        name: DEMO_TASK_NAME,
        description:
          'SIEM read access for INC-2026-0042 plus EDR host-isolation authority ' +
          `for ${DEMO_HOST_ID} (isolation requires human approval). Deliberately ` +
          'excludes any IAM/firewall action — out of scope for this task.',
        assignedAgentId: socResponseAgentId,
        allowedToolActions: [
          { toolId: 'siem', actionId: 'search-events' },
          { toolId: 'siem', actionId: 'fetch-incident' },
          { toolId: 'edr', actionId: 'get-host' },
          { toolId: 'edr', actionId: 'isolate-host' },
        ],
        allowedResourceSelectors: [
          { toolId: 'siem', pattern: '*' },
          { toolId: 'edr', pattern: DEMO_HOST_ID },
        ],
        forbiddenActions: [],
        expiresAt: new Date(
          Date.now() + 30 * 24 * 60 * 60 * 1000,
        ).toISOString(),
        riskCeiling: 50,
      },
    });
    this.logger.log(`Created task "${DEMO_TASK_NAME}" (id=${created.id})`);
    return created;
  }

  // ---- Microsoft catalog against the DEMO FIXTURE (ADR-0004) ----

  /**
   * Registers `microsoft-graph`/`microsoft-defender` against the fixture
   * served by demo-soc-tools, a policy requiring approval for every
   * Microsoft mutation, and a task letting the SOC Response Agent read the
   * fixture incident and, with approval, disable its user and isolate its
   * device. Everything here is DEMO FIXTURE data, not a live tenant.
   */
  private async ensureMicrosoftFixture(
    tenantId: string,
    options: DemoSeedOptions,
    ownerToken: string,
    socResponseAgentId: string,
  ): Promise<{ id: string }> {
    await this.openBaoKvClient.writeSecret(MICROSOFT_FIXTURE_KV_PATH, {
      value: MICROSOFT_FIXTURE_APP.clientSecret,
    });
    const tenantClient = await this.tenantDatabaseManager.getClient(tenantId);
    await ensureMicrosoftFixtureTools(tenantClient, {
      fixtureBaseUrl: options.microsoftFixtureUrl,
      kvPath: MICROSOFT_FIXTURE_KV_PATH,
    });
    await this.ensurePolicies(options.apiEndpoint, ownerToken, [
      {
        name: 'Microsoft Connector Approval Policy',
        description:
          'Every Microsoft Graph/Defender mutation needs a human approval; reads are allowed.',
        content: microsoftPolicyContent(),
      },
    ]);

    const existing = await tenantClient.task.findFirst({
      where: { name: MICROSOFT_TASK_NAME },
    });
    if (existing) return existing;
    const { userId, machineId, incidentId } = MICROSOFT_FIXTURE_IDS;
    const created = await this.httpJson<{ id: string }>(
      options.apiEndpoint,
      '/tasks',
      {
        method: 'POST',
        token: ownerToken,
        body: {
          name: MICROSOFT_TASK_NAME,
          description:
            'DEMO FIXTURE: read Defender XDR incident 4201 and its alerts, investigate the ' +
            'user and device, and (with human approval) disable the user, revoke sessions ' +
            'and isolate the device.',
          assignedAgentId: socResponseAgentId,
          allowedToolActions: [
            ...[
              'security.incident.list',
              'security.incident.get',
              'security.alert.list',
              'entra.user.get',
              'entra.user.signins.list',
              'entra.user.risk.get',
              'entra.user.disable',
              'entra.user.sessions.revoke',
            ].map((actionId) => ({ toolId: MICROSOFT_GRAPH_TOOL, actionId })),
            ...[
              'defender.machine.get',
              'defender.machineaction.list',
              'defender.machine.isolate',
            ].map((actionId) => ({
              toolId: MICROSOFT_DEFENDER_TOOL,
              actionId,
            })),
          ],
          allowedResourceSelectors: [
            { toolId: MICROSOFT_GRAPH_TOOL, pattern: 'all' },
            { toolId: MICROSOFT_GRAPH_TOOL, pattern: incidentId },
            { toolId: MICROSOFT_GRAPH_TOOL, pattern: userId },
            { toolId: MICROSOFT_DEFENDER_TOOL, pattern: machineId },
          ],
          forbiddenActions: [],
          expiresAt: new Date(
            Date.now() + 30 * 24 * 60 * 60 * 1000,
          ).toISOString(),
          riskCeiling: 50,
        },
      },
    );
    this.logger.log(
      `Created task "${MICROSOFT_TASK_NAME}" (id=${created.id}) against the Microsoft DEMO FIXTURE`,
    );
    return created;
  }

  /** The Python LLM SOC agent's task against the fixture (ADR-0002). Idempotent by name. */
  private async ensureSocLlmTask(
    tenantId: string,
    apiEndpoint: string,
    ownerToken: string,
    agentId: string,
  ): Promise<{ id: string }> {
    const tenantClient = await this.tenantDatabaseManager.getClient(tenantId);
    const existing = await tenantClient.task.findFirst({
      where: { name: SOC_LLM_TASK_NAME, status: 'ACTIVE' },
    });
    if (existing && existing.expiresAt > new Date()) return existing;
    const created = await this.httpJson<{ id: string }>(apiEndpoint, '/tasks', {
      method: 'POST',
      token: ownerToken,
      body: {
        name: SOC_LLM_TASK_NAME,
        description:
          'DEMO FIXTURE: triage Defender XDR incident 4201 with the LLM SOC agent: read the ' +
          'incident, alerts, user and device; disable the user and isolate the device only ' +
          'with human approval.',
        assignedAgentId: agentId,
        ...socAgentTaskGrants(),
        expiresAt: new Date(
          Date.now() + 30 * 24 * 60 * 60 * 1000,
        ).toISOString(),
        riskCeiling: 50,
      },
    });
    this.logger.log(
      `Created task "${SOC_LLM_TASK_NAME}" (id=${created.id}) for the LLM SOC agent`,
    );
    return created;
  }

  @Option({
    flags: '--microsoft-fixture-url <url>',
    description:
      'Base URL of demo-soc-tools serving the Microsoft DEMO FIXTURE (e.g. http://localhost:3101); registers the Microsoft catalog against it',
    defaultValue: process.env.MICROSOFT_FIXTURE_BASE_URL ?? '',
  })
  parseMicrosoftFixtureUrl(value: string): string {
    return value;
  }

  @Option({
    flags: '--api-endpoint <url>',
    description:
      "manar-api's human-facing HTTP endpoint (must already be running)",
    defaultValue:
      process.env.MANAR_DEMO_API_ENDPOINT ?? 'http://localhost:3000',
  })
  parseApiEndpoint(value: string): string {
    return value;
  }

  @Option({
    flags: '--demo-tools-base-url <url>',
    description: 'Base URL of the real running packages/demo-soc-tools service',
    defaultValue:
      process.env.DEMO_SOC_TOOLS_BASE_URL ?? 'http://localhost:3101',
  })
  parseDemoToolsBaseUrl(value: string): string {
    return value;
  }

  @Option({
    flags: '--demo-tools-api-key <key>',
    description: 'Bearer API key the demo-soc-tools service accepts',
    defaultValue: process.env.DEMO_TOOLS_API_KEY ?? 'manar-dev-demo-tools-key',
  })
  parseDemoToolsApiKey(value: string): string {
    return value;
  }
}
