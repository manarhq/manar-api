import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import { FileIdentityStore, ManarAgent } from '@manar/sdk-node';
import type { AgentIdentity } from '@manar/sdk-node';
import { AppModule } from '../src/app.module';
import { AgentMtlsAppModule } from '../src/agent-mtls/agent-mtls-app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';

/**
 * Phase 15a (Section 53) mandatory scenario: "a seeded policy denies/
 * requires-approval for a RESTRICTED action, verified via the real
 * authorize pipeline." Mirrors `test/policy-risk.e2e-spec.ts`'s exact
 * boilerplate (real HTTP server, real Postgres/Keycloak/OpenBao/OpenFGA).
 *
 * The `AiAdvisoryClient`/`RESTRICTED`-blocks-external-AI scenario (the
 * other mandatory scenario for this phase, asserted "at the transport
 * level") is covered by
 * `src/ai-advisory/ai-advisory-client.service.spec.ts`'s "data
 * classification enforcement (Section 53)" suite — the exact same file
 * and pattern Phase 12a's own residency scenario already used (a real
 * fake gRPC server, `fakeServer.callCounts` asserted at 0), not a
 * separate e2e file.
 */
describe('Data classification (e2e)', () => {
  let humanApp: NestFastifyApplication;
  let agentMtlsApp: NestFastifyApplication;
  let humanEndpoint: string;
  let agentMtlsEndpoint: string;

  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let adminToken: string;

  const ADMIN_USERNAME = `classification-admin-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `dc-${label}-${randomUUID().slice(0, 8)}`;
  }

  async function dropRealDatabase(databaseName: string): Promise<void> {
    const admin = new PgClient({
      connectionString: process.env.CONTROL_DATABASE_URL,
    });
    await admin.connect();
    try {
      await admin.query(
        `DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`,
      );
    } finally {
      await admin.end();
    }
  }

  async function cleanupTenant(t: ProvisionedTenant): Promise<void> {
    if (t.keycloakRealm) await deleteRealm(t.keycloakRealm);
    if (t.databaseBinding?.databaseName) {
      await dropRealDatabase(t.databaseBinding.databaseName);
    }
    await control.tenantDatabaseBinding.deleteMany({
      where: { tenantId: t.id },
    });
    await control.secretReference.deleteMany({ where: { tenantId: t.id } });
    await control.tenant.deleteMany({ where: { id: t.id } });
  }

  async function createEnrolledAgent(slugLabel: string): Promise<{
    agentId: string;
    slug: string;
    identity: AgentIdentity;
    manar: ManarAgent;
  }> {
    const slug = uniqueSlug(slugLabel);
    const createResponse = await request(humanApp.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ slug, displayName: `Test agent ${slug}` })
      .expect(201);
    const agentId = (createResponse.body as { id: string }).id;

    const tokenResponse = await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/enrollment-tokens`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(201);
    const rawToken = (tokenResponse.body as { token: string }).token;

    const identityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase-not-for-production',
    );
    const manar = new ManarAgent({
      endpoint: humanEndpoint,
      mtlsEndpoint: agentMtlsEndpoint,
      identityStore,
    });
    const identity = await manar.enroll(rawToken);
    return { agentId, slug, identity, manar };
  }

  interface GrantInput {
    toolId: string;
    actionId: string;
  }
  interface ResourceInput {
    toolId: string;
    pattern: string;
  }

  async function createTask(input: {
    assignedAgentId: string;
    allowedToolActions: GrantInput[];
    allowedResourceSelectors: ResourceInput[];
    riskCeiling?: number;
  }): Promise<{ id: string; status: string; expiresAt: string }> {
    const response = await request(humanApp.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: `Test task ${randomUUID().slice(0, 8)}`,
        assignedAgentId: input.assignedAgentId,
        allowedToolActions: input.allowedToolActions,
        allowedResourceSelectors: input.allowedResourceSelectors,
        forbiddenActions: [],
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        riskCeiling: input.riskCeiling,
      })
      .expect(201);
    return response.body as { id: string; status: string; expiresAt: string };
  }

  interface PolicyRuleInput {
    toolId: string;
    actionId: string;
    resourcePattern?: string;
    effect: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';
    resourceClassification?:
      'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
    riskWeight?: number;
    riskFloor?: number;
  }

  async function createPublishedPolicy(
    name: string,
    rules: PolicyRuleInput[],
  ): Promise<{ policyId: string }> {
    const createResponse = await request(humanApp.getHttpServer() as App)
      .post('/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name, content: { rules } })
      .expect(201);
    const body = createResponse.body as {
      id: string;
      latestVersion: { id: string };
    };
    await request(humanApp.getHttpServer() as App)
      .post(`/policies/${body.id}/versions/${body.latestVersion.id}/publish`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(201);
    return { policyId: body.id };
  }

  /** Writes `Tool`/`ToolAction` rows directly against the real tenant database — no human-facing registration API exists (out of scope, see docs/tool-gateway.md). */
  async function registerToolWithAction(input: {
    toolName: string;
    actionName: string;
    classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  }): Promise<void> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const tool = await tenantClient.tool.create({
      data: {
        name: input.toolName,
        type: 'TEST',
        baseEndpoint: 'http://127.0.0.1:1/unused',
        protocol: 'HTTP',
        credentialReference: { provider: 'ENV', reference: 'UNUSED' },
        enabled: true,
      },
    });
    await tenantClient.toolAction.create({
      data: {
        toolId: tool.id,
        name: input.actionName,
        riskBaseScore: 5,
        classification: input.classification,
      },
    });
  }

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    }).compile();
    humanApp = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await humanApp.init();
    await humanApp.getHttpAdapter().getInstance().ready();
    await humanApp.listen(0, '127.0.0.1');
    const humanAddress = humanApp.getHttpServer().address() as AddressInfo;
    humanEndpoint = `http://127.0.0.1:${humanAddress.port}`;

    const agentMtlsFixture: TestingModule = await Test.createTestingModule({
      imports: [AgentMtlsAppModule],
    }).compile();
    agentMtlsApp =
      agentMtlsFixture.createNestApplication<NestFastifyApplication>(
        new FastifyAdapter({
          https: {
            cert: readFileSync(
              process.env.AGENT_MTLS_SERVER_CERT_PATH ??
                'deploy/openbao/server-cert.pem',
            ),
            key: readFileSync(
              process.env.AGENT_MTLS_SERVER_KEY_PATH ??
                'deploy/openbao/server-key.pem',
            ),
            ca: readFileSync(
              process.env.AGENT_MTLS_CLIENT_CA_PATH ??
                'deploy/openbao/ca-chain.pem',
            ),
            requestCert: true,
            rejectUnauthorized: true,
          },
        }),
      );
    await agentMtlsApp.init();
    await agentMtlsApp.getHttpAdapter().getInstance().ready();
    await agentMtlsApp.listen(0, '127.0.0.1');
    const mtlsAddress = agentMtlsApp.getHttpServer().address() as AddressInfo;
    agentMtlsEndpoint = `https://127.0.0.1:${mtlsAddress.port}`;

    control = humanApp.get(ControlPrismaService);
    tenantDatabaseManager = humanApp.get(TenantDatabaseManager);
    provisioning = moduleFixture.get(TenantProvisioningService);

    tenant = await provisioning.provisionTenant({
      slug: uniqueSlug('tenant'),
      name: 'Data Classification Test Tenant',
    });
    if (!tenant.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }

    const clientSecretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });

    const adminUserId = await createRealmUser(tenant.keycloakRealm, {
      username: ADMIN_USERNAME,
      email: `${ADMIN_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm, adminUserId, 'SECURITY_ADMIN');

    adminToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username: ADMIN_USERNAME,
      password: USER_PASSWORD,
    });
  }, 120_000);

  afterAll(async () => {
    await humanApp.close();
    await agentMtlsApp.close();
    if (tenant) await cleanupTenant(tenant);
    await control.$disconnect();
  }, 60_000);

  it('a policy resourceClassification: RESTRICTED rule requires approval for a RESTRICTED-classified action, via the real authorize pipeline', async () => {
    const toolName = uniqueSlug('iam');
    await registerToolWithAction({
      toolName,
      actionName: 'disable-user',
      classification: 'RESTRICTED',
    });
    await createPublishedPolicy(uniqueSlug('restricted-approval'), [
      {
        toolId: toolName,
        actionId: '*',
        effect: 'REQUIRE_APPROVAL',
        resourceClassification: 'RESTRICTED',
        riskFloor: 60,
      },
    ]);

    const agent = await createEnrolledAgent('restricted');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: toolName, actionId: 'disable-user' }],
      allowedResourceSelectors: [{ toolId: toolName, pattern: '*' }],
      riskCeiling: 100,
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: toolName,
      actionId: 'disable-user',
      resource: 'user-1',
    });
    expect(decision.decision).toBe('REQUIRE_APPROVAL');
    if (decision.decision === 'REQUIRE_APPROVAL') {
      expect(decision.reason).toBe('policy_requires_approval');
      expect(decision.riskScore).toBeGreaterThanOrEqual(60);
    }
  }, 30_000);

  it('a policy resourceClassification: RESTRICTED rule does NOT match an INTERNAL-classified action -> pass-through ALLOW', async () => {
    const toolName = uniqueSlug('iam-internal');
    await registerToolWithAction({
      toolName,
      actionName: 'get-user',
      classification: 'INTERNAL',
    });
    await createPublishedPolicy(uniqueSlug('restricted-approval-2'), [
      {
        toolId: toolName,
        actionId: '*',
        effect: 'DENY',
        resourceClassification: 'RESTRICTED',
      },
    ]);

    const agent = await createEnrolledAgent('internal');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: toolName, actionId: 'get-user' }],
      allowedResourceSelectors: [{ toolId: toolName, pattern: '*' }],
      riskCeiling: 100,
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: toolName,
      actionId: 'get-user',
      resource: 'user-1',
    });
    expect(decision.decision).toBe('ALLOW');
  }, 30_000);

  it("RiskEngine's classification contributor alone (no policy at all) can push a request over task.riskCeiling into REQUIRE_APPROVAL -- mirrors test/policy-risk.e2e-spec.ts's identical risk-ceiling scenario, with classification as the contributor instead of a destructive keyword", async () => {
    const confidentialTool = uniqueSlug('confidential');
    // Deterministic score: baseline(10) + riskBaseScore(5) +
    // classification(CONFIDENTIAL:10) = 25 -- see docs/data-classification.md.
    // No policy published for this tool/action at all.
    await registerToolWithAction({
      toolName: confidentialTool,
      actionName: 'read',
      classification: 'CONFIDENTIAL',
    });

    const agent = await createEnrolledAgent('confidential');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: confidentialTool, actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: confidentialTool, pattern: '*' }],
      riskCeiling: 20, // below 25 -- AI advisory can only push the final score up further, never down, so this stays REQUIRE_APPROVAL regardless of AI availability
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: confidentialTool,
      actionId: 'read',
      resource: 'anything',
    });
    expect(decision.decision).toBe('REQUIRE_APPROVAL');
    if (decision.decision === 'REQUIRE_APPROVAL') {
      expect(decision.reason).toBe('risk_ceiling_exceeded');
      expect(decision.riskScore).toBeGreaterThanOrEqual(25);
    }
  }, 30_000);
});
