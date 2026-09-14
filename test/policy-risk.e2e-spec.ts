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
import {
  AuthorizeDecision,
  FileIdentityStore,
  ManarAgent,
} from '@manar/sdk-node';
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
 * Mandatory Phase 6 (Policy & Risk Engine) scenarios — design spec's
 * "Testing" section — run against a real HTTP server, real local
 * Postgres, real local Keycloak, real local OpenBao, and real local
 * OpenFGA (`pnpm infra:up`), reusing the real Phase 4/5 SDK+enrollment+
 * task machinery to set up scenarios rather than reaching into the DB
 * directly wherever an API path exists (the one deliberate exception is
 * the "simulated policy-load failure" scenario, which has no API path by
 * design — see that test).
 */
describe('Policy & Risk Engine (e2e)', () => {
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

  const ADMIN_USERNAME = `policy-admin-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `policy-${label}-${randomUUID().slice(0, 8)}`;
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

  /** Creates a PENDING_ENROLLMENT agent + enrollment token via the real human HTTP API, then enrolls it via the real SDK against the real mTLS listener. */
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

  /** Creates a root Task via the real human HTTP API. */
  async function createTask(input: {
    assignedAgentId: string;
    allowedToolActions: GrantInput[];
    allowedResourceSelectors: ResourceInput[];
    forbiddenActions?: GrantInput[];
    expiresAt?: Date;
    maxExecutions?: number;
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
        forbiddenActions: input.forbiddenActions ?? [],
        expiresAt: (
          input.expiresAt ?? new Date(Date.now() + 3_600_000)
        ).toISOString(),
        maxExecutions: input.maxExecutions,
        riskCeiling: input.riskCeiling,
      })
      .expect(201);
    return response.body as { id: string; status: string; expiresAt: string };
  }

  interface PolicyRuleInput {
    toolId: string;
    actionId: string;
    resourcePattern?: string;
    effect: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
    riskWeight?: number;
    riskFloor?: number;
  }

  interface PolicyVersionResponse {
    id: string;
    policyId: string;
    version: number;
    status: string;
    content: { rules: PolicyRuleInput[] };
    contentHash: string;
    reason: string | null;
    previousVersionId: string | null;
    publishedAt: string | null;
  }

  /** Creates a Policy (+ its first DRAFT version) via the real human HTTP API. */
  async function createPolicy(
    name: string,
    rules: PolicyRuleInput[],
  ): Promise<{ id: string; latestVersion: PolicyVersionResponse }> {
    const response = await request(humanApp.getHttpServer() as App)
      .post('/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name, content: { rules } })
      .expect(201);
    return response.body as {
      id: string;
      latestVersion: PolicyVersionResponse;
    };
  }

  async function publishVersion(
    policyId: string,
    versionId: string,
  ): Promise<PolicyVersionResponse> {
    const response = await request(humanApp.getHttpServer() as App)
      .post(`/policies/${policyId}/versions/${versionId}/publish`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(201);
    return response.body as PolicyVersionResponse;
  }

  /** Creates a Policy, publishes its first version, and returns both. */
  async function createPublishedPolicy(
    name: string,
    rules: PolicyRuleInput[],
  ): Promise<{ policyId: string; version: PolicyVersionResponse }> {
    const { id: policyId, latestVersion } = await createPolicy(name, rules);
    const version = await publishVersion(policyId, latestVersion.id);
    return { policyId, version };
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
      name: 'Policy & Risk Engine Test Tenant',
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
    // SECURITY_ADMIN covers both the general /policies role gate and the
    // narrower publish-only role gate in a single test user.
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

  it('1. a policy DENY rule overrides what OpenFGA/task-scope would otherwise allow', async () => {
    await createPublishedPolicy(uniqueSlug('deny-override'), [
      { toolId: 'iam', actionId: 'delete_user', effect: 'DENY' },
    ]);

    const agent = await createEnrolledAgent('deny');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      // OpenFGA/task-scope grants this action outright.
      allowedToolActions: [{ toolId: 'iam', actionId: 'delete_user' }],
      allowedResourceSelectors: [{ toolId: 'iam', pattern: '*' }],
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'iam',
      actionId: 'delete_user',
      resource: 'user-123',
    });
    expect(decision.decision).toBe('DENY');
    if (decision.decision === 'DENY') {
      expect(decision.reason).toBe('policy_denied');
    }
  }, 30_000);

  it('2. a policy APPROVAL_REQUIRED rule produces that outcome even for a low-risk-scored action', async () => {
    await createPublishedPolicy(uniqueSlug('approval-override'), [
      {
        toolId: 'edr',
        actionId: 'read_status',
        effect: 'APPROVAL_REQUIRED',
        // No riskWeight/riskFloor at all -- the action itself is
        // low-risk (no destructive keyword, root task, no policy risk
        // contribution), yet the policy's own effect still forces
        // APPROVAL_REQUIRED.
      },
    ]);

    const agent = await createEnrolledAgent('approval');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'edr', actionId: 'read_status' }],
      allowedResourceSelectors: [{ toolId: 'edr', pattern: '*' }],
      riskCeiling: 100, // generous -- proves this isn't the risk-ceiling path
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'edr',
      actionId: 'read_status',
      resource: 'host-1',
    });
    expect(decision.decision).toBe('APPROVAL_REQUIRED');
    if (decision.decision === 'APPROVAL_REQUIRED') {
      expect(decision.reason).toBe('policy_requires_approval');
      expect(decision.riskScore).toBeLessThan(20);
    }
  }, 30_000);

  it('3. exceeding task.riskCeiling produces APPROVAL_REQUIRED even with no matching policy rule', async () => {
    const agent = await createEnrolledAgent('riskceil');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      // A destructive-keyword action ("isolate") pushes the deterministic
      // score well above a very low riskCeiling -- no policy published
      // for this tool/action at all.
      allowedToolActions: [{ toolId: 'edr', actionId: 'isolate_host' }],
      allowedResourceSelectors: [{ toolId: 'edr', pattern: '*' }],
      riskCeiling: 5,
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'edr',
      actionId: 'isolate_host',
      resource: 'host-1',
    });
    expect(decision.decision).toBe('APPROVAL_REQUIRED');
    if (decision.decision === 'APPROVAL_REQUIRED') {
      expect(decision.reason).toBe('risk_ceiling_exceeded');
      expect(decision.riskScore).toBeGreaterThan(5);
    }
  }, 30_000);

  it('4. no matching policy rule + within risk ceiling -> ALLOW (pass-through default)', async () => {
    // A published policy exists, but for a completely unrelated tool --
    // proves this is genuine pass-through, not "no policies published at
    // all" being a degenerate special case.
    await createPublishedPolicy(uniqueSlug('unrelated'), [
      { toolId: 'iam', actionId: '*', effect: 'DENY' },
    ]);

    const agent = await createEnrolledAgent('passthru');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      riskCeiling: 20,
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(decision).toEqual<AuthorizeDecision>({ decision: 'ALLOW' });
  }, 30_000);

  it('5. the API never exposes an update/delete path for a published policy version', async () => {
    const { policyId, version } = await createPublishedPolicy(
      uniqueSlug('immutable'),
      [{ toolId: 'fs', actionId: 'read', effect: 'ALLOW' }],
    );

    // No PUT/PATCH/DELETE handler exists on this path at all -- Nest's
    // router has nothing registered for it, so these 404 rather than
    // 403/405. Proves absence of the capability at the routing layer,
    // not merely a permission check blocking it.
    await request(humanApp.getHttpServer() as App)
      .put(`/policies/${policyId}/versions/${version.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ content: { rules: [] } })
      .expect(404);

    await request(humanApp.getHttpServer() as App)
      .patch(`/policies/${policyId}/versions/${version.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ content: { rules: [] } })
      .expect(404);

    await request(humanApp.getHttpServer() as App)
      .delete(`/policies/${policyId}/versions/${version.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(404);

    // The version itself is provably untouched.
    const stillThere = await request(humanApp.getHttpServer() as App)
      .get(`/policies/${policyId}/versions/${version.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
    expect((stillThere.body as PolicyVersionResponse).contentHash).toBe(
      version.contentHash,
    );
  }, 30_000);

  it('6. rollback: publish v1, publish v2, roll back -> v3 with v1 content, chain intact, v1/v2 still readable unchanged', async () => {
    const name = uniqueSlug('rollback');
    const { id: policyId, latestVersion: v1Draft } = await createPolicy(name, [
      { toolId: 'fs', actionId: 'read', effect: 'ALLOW' },
    ]);
    const v1 = await publishVersion(policyId, v1Draft.id);

    const v2DraftResponse = await request(humanApp.getHttpServer() as App)
      .post(`/policies/${policyId}/versions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        content: {
          rules: [{ toolId: 'fs', actionId: 'write', effect: 'DENY' }],
        },
      })
      .expect(201);
    const v2Draft = v2DraftResponse.body as PolicyVersionResponse;
    const v2 = await publishVersion(policyId, v2Draft.id);

    expect(v2.version).toBe(2);
    expect(v2.previousVersionId).toBe(v1.id);

    // Rollback: a new DRAFT version whose content matches v1's.
    const v3DraftResponse = await request(humanApp.getHttpServer() as App)
      .post(`/policies/${policyId}/versions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ rollbackToVersionId: v1.id })
      .expect(201);
    const v3Draft = v3DraftResponse.body as PolicyVersionResponse;
    const v3 = await publishVersion(policyId, v3Draft.id);

    expect(v3.version).toBe(3);
    // previousVersionId is the chain predecessor (v2), NOT the version
    // whose content was reused (v1) -- see docs/policy-model.md.
    expect(v3.previousVersionId).toBe(v2.id);
    expect(v3.contentHash).toBe(v1.contentHash);
    expect(v3.reason).toMatch(/rollback/i);
    expect(v3.reason).toContain('1');

    // v1 and v2 remain individually readable and unchanged.
    const v1Readback = await request(humanApp.getHttpServer() as App)
      .get(`/policies/${policyId}/versions/${v1.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
    expect((v1Readback.body as PolicyVersionResponse).contentHash).toBe(
      v1.contentHash,
    );
    expect((v1Readback.body as PolicyVersionResponse).status).toBe('PUBLISHED');

    const v2Readback = await request(humanApp.getHttpServer() as App)
      .get(`/policies/${policyId}/versions/${v2.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
    expect((v2Readback.body as PolicyVersionResponse).contentHash).toBe(
      v2.contentHash,
    );

    // The current published content is now v3's (== v1's content).
    const current = await request(humanApp.getHttpServer() as App)
      .get(`/policies/${policyId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
    expect(
      (current.body as { currentVersion: PolicyVersionResponse }).currentVersion
        .id,
    ).toBe(v3.id);

    // Full history has all three, oldest first.
    const history = await request(humanApp.getHttpServer() as App)
      .get(`/policies/${policyId}/versions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);
    const historyVersions = (history.body as PolicyVersionResponse[]).map(
      (v) => v.version,
    );
    expect(historyVersions).toEqual([1, 2, 3]);
  }, 30_000);

  it('7. a YAML policy and its JSON equivalent produce an identical stored contentHash', async () => {
    const jsonResponse = await request(humanApp.getHttpServer() as App)
      .post('/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: uniqueSlug('yaml-json-a'),
        content: {
          rules: [
            {
              toolId: 'soc',
              actionId: 'read',
              effect: 'ALLOW',
              riskWeight: 15,
            },
          ],
        },
      })
      .expect(201);

    const yamlResponse = await request(humanApp.getHttpServer() as App)
      .post('/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: uniqueSlug('yaml-json-b'),
        contentYaml: [
          'rules:',
          '  - riskWeight: 15',
          '    effect: ALLOW',
          '    actionId: read',
          '    toolId: soc',
        ].join('\n'),
      })
      .expect(201);

    const jsonBody = jsonResponse.body as {
      latestVersion: PolicyVersionResponse;
    };
    const yamlBody = yamlResponse.body as {
      latestVersion: PolicyVersionResponse;
    };
    expect(yamlBody.latestVersion.contentHash).toBe(
      jsonBody.latestVersion.contentHash,
    );
  }, 30_000);

  it('8. two published policies both matching the same request combine most-restrictive-wins (ALLOW + DENY -> DENY)', async () => {
    const toolId = 'combine';
    const actionId = uniqueSlug('action').replace(/-/g, '_');

    await createPublishedPolicy(uniqueSlug('combine-allow'), [
      { toolId, actionId, effect: 'ALLOW' },
    ]);
    await createPublishedPolicy(uniqueSlug('combine-deny'), [
      { toolId, actionId, effect: 'DENY' },
    ]);

    const agent = await createEnrolledAgent('combine');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId, actionId }],
      allowedResourceSelectors: [{ toolId, pattern: '*' }],
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId,
      actionId,
      resource: 'anything',
    });
    expect(decision.decision).toBe('DENY');
    if (decision.decision === 'DENY') {
      expect(decision.reason).toBe('policy_denied');
    }
  }, 30_000);

  it('9. a simulated policy-load failure (malformed content bypassing normal validation) fails closed to DENY', async () => {
    // There is no API path that can ever write malformed PolicyVersion
    // content (both the JSON and YAML submission paths validate against
    // PolicyContentSchema before any write) -- the design spec's own
    // Testing section calls this out explicitly: simulate the bypass
    // directly against the tenant database, exactly like the Phase 5
    // suite's "expired task" scenario backdates expiresAt directly.
    const agent = await createEnrolledAgent('loadfail');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    // Confirm it works before corrupting a policy.
    const before = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(before).toEqual<AuthorizeDecision>({ decision: 'ALLOW' });

    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const authorProfile = await tenantClient.userProfile.findFirstOrThrow();
    const corruptPolicy = await tenantClient.policy.create({
      data: { name: uniqueSlug('corrupt') },
    });
    await tenantClient.policyVersion.create({
      data: {
        policyId: corruptPolicy.id,
        version: 1,
        status: 'PUBLISHED',
        // Malformed on purpose -- bypasses PolicyContentSchema entirely,
        // written directly against the tenant database.
        content: { totallyNotRules: true },
        contentHash: 'irrelevant-for-this-test',
        authorId: authorProfile.id,
        publishedAt: new Date(),
      },
    });

    const after = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(after.decision).toBe('DENY');
    if (after.decision === 'DENY') {
      expect(after.reason).toBe('policy_evaluation_failed');
    }
  }, 30_000);
});
