import 'dotenv/config';
import * as https from 'node:https';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import { NativeConnection, Worker } from '@temporalio/worker';
import { FileIdentityStore, ManarAgent } from '@manar/sdk-node';
import type { AgentIdentity, AuthorizeDecision } from '@manar/sdk-node';
import { AppModule } from '../src/app.module';
import { AgentMtlsAppModule } from '../src/agent-mtls/agent-mtls-app.module';
import { WorkerAppModule } from '../src/temporal/worker-app.module';
import { ApprovalActivitiesFactory } from '../src/temporal/activities/approval.activities';
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
import { HttpFixtureServer } from './support/http-fixture-server';
import { ensureManarConnector } from '../src/cli/commands/manar-connector-register.command';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';

/**
 * Kill Switches (all five scopes) — every mandatory scenario from the
 * design spec's "Testing" section
 * (docs/superpowers/specs/2026-08-19-phase-killswitch-design.md), run
 * against real Postgres/Keycloak/OpenBao/OpenFGA/Temporal/Kafka
 * (`pnpm infra:up`). See docs/kill-switches.md.
 *
 * Reuses the real SDK (`ManarAgent.enroll`/`.authorize`) for every
 * ALLOW/DENY check this suite drives (tests 1-4, 6), and the same raw-mTLS
 * `/agent/v1/tools/invoke` + `/agent/v1/approvals/:id` + in-process
 * Temporal worker pattern `test/approvals.e2e-spec.ts` already established
 * for the one scenario that needs a real grant (test 5) — no direct DB
 * manipulation anywhere a real API path exists. The one deliberate
 * exception: creating an `AgentGroup` + membership directly via
 * `tenantClient` (test 3) — this phase's spec only asks for the
 * kill-switch endpoint on that scope, not a full AgentGroup CRUD API, so
 * there is no real API path to create one through.
 *
 * Test 7 (platform scope) activates the one genuinely cross-tenant,
 * process-wide switch against the real, shared control DB — every other
 * concurrently-running e2e file's `/agent/v1/authorize` calls would also
 * see DENY for as long as it stays active. The window between activation
 * and deactivation is kept as small as possible (a `try`/`finally`
 * wrapping only the two DENY assertions) to minimize cross-file
 * interference risk under Vitest's default parallel file execution; a
 * `beforeAll` safety net also force-deactivates it up front in case a
 * previous crashed run left it on.
 */
describe('Kill Switches (e2e)', () => {
  let humanApp: NestFastifyApplication;
  let agentMtlsApp: NestFastifyApplication;
  let humanEndpoint: string;
  let agentMtlsEndpoint: string;
  let agentMtlsPort: number;
  let fullCaChainPem: string;

  let temporalConnection: NativeConnection;
  let temporalWorker: Worker;
  let temporalWorkerRunPromise: Promise<void>;
  let workerModuleFixture: TestingModule;

  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let adminToken: string;
  let tenant2: ProvisionedTenant;
  let adminToken2: string;

  const PLATFORM_OPERATOR_TOKEN =
    process.env.PLATFORM_KILL_SWITCH_OPERATOR_TOKEN ??
    'dev-only-platform-kill-switch-operator-token-change-me';

  const ADMIN_USERNAME = `ks-admin-${randomUUID().slice(0, 8)}`;
  const ADMIN_USERNAME_2 = `ks-admin2-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `ks-${label}-${randomUUID().slice(0, 8)}`;
  }

  /** Short form for tenant/agent slugs — Agent.identifier is a CSR SAN, empirically rejected by OpenBao's PKI signing once it exceeds 63 chars (see test/approvals.e2e-spec.ts's identical helper). */
  function shortSlug(label: string): string {
    return `ks-${label}-${randomUUID().slice(0, 8)}`;
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

  async function provisionTestTenant(
    slugLabel: string,
    username: string,
  ): Promise<{ tenant: ProvisionedTenant; token: string }> {
    const provisioned = await provisioning.provisionTenant({
      slug: shortSlug(slugLabel),
      name: `Kill Switch Test Tenant ${slugLabel}`,
    });
    if (!provisioned.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }
    const clientSecretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: provisioned.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    const userId = await createRealmUser(provisioned.keycloakRealm, {
      username,
      email: `${username}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(provisioned.keycloakRealm, userId, 'SECURITY_ADMIN');
    const token = await getUserToken({
      realm: provisioned.keycloakRealm,
      clientId: provisioned.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username,
      password: USER_PASSWORD,
    });
    return { tenant: provisioned, token };
  }

  /** Creates a PENDING_ENROLLMENT agent + enrollment token via the real human HTTP API, then enrolls it via the real SDK — same pattern as test/task-delegation.e2e-spec.ts. */
  async function createEnrolledAgent(
    slugLabel: string,
    token: string = adminToken,
  ): Promise<{
    agentId: string;
    slug: string;
    identity: AgentIdentity;
    manar: ManarAgent;
  }> {
    const slug = shortSlug(slugLabel);
    const createResponse = await request(humanApp.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${token}`)
      .send({ slug, displayName: `Test agent ${slug}` })
      .expect(201);
    const agentId = (createResponse.body as { id: string }).id;

    const tokenResponse = await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/enrollment-tokens`)
      .set('Authorization', `Bearer ${token}`)
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

  async function createTask(
    input: {
      assignedAgentId: string;
      allowedToolActions: GrantInput[];
      allowedResourceSelectors: ResourceInput[];
      riskCeiling?: number;
    },
    token: string = adminToken,
  ): Promise<{ id: string; status: string; expiresAt: string }> {
    const response = await request(humanApp.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: `Kill switch test task ${randomUUID().slice(0, 8)}`,
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

  async function registerTool(
    tenantId: string,
    input: { name: string; baseEndpoint: string },
  ): Promise<{ id: string; name: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenantId);
    return tenantClient.tool.create({
      data: {
        name: input.name,
        type: 'TEST',
        baseEndpoint: input.baseEndpoint,
        protocol: 'HTTP',
        credentialReference: { provider: 'ENV', reference: 'PATH' },
        enabled: true,
      },
    });
  }

  async function registerToolAction(
    tenantId: string,
    input: { toolId: string; name: string; riskBaseScore?: number },
  ): Promise<{ id: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenantId);
    return tenantClient.toolAction.create({
      data: {
        toolId: input.toolId,
        name: input.name,
        riskBaseScore: input.riskBaseScore ?? 90,
        inputSchema: { type: 'object' },
      },
    });
  }

  /** No AgentGroup CRUD API exists this phase (only its kill-switch endpoint does — see design spec's "out of scope") — this is the one deliberate direct-DB-write in this suite. */
  async function createAgentGroupWithMember(
    tenantId: string,
    agentId: string,
    name: string,
  ): Promise<{ id: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenantId);
    const group = await tenantClient.agentGroup.create({ data: { name } });
    await tenantClient.agentGroupMembership.create({
      data: { agentId, groupId: group.id },
    });
    return group;
  }

  interface KillSwitchStatusBody {
    id: string;
    scope: string;
    targetId: string | null;
    active: boolean;
    reason: string | null;
    activatedAt: string;
  }
  interface PlatformKillSwitchStatusBody {
    active: boolean;
    reason: string | null;
    activatedAt: string | null;
  }

  async function activateTenantKillSwitch(
    token: string,
    reason?: string,
  ): Promise<KillSwitchStatusBody> {
    const res = await request(humanApp.getHttpServer() as App)
      .post('/tenants/kill-switch')
      .set('Authorization', `Bearer ${token}`)
      .send(reason ? { reason } : {})
      .expect(201);
    return res.body as KillSwitchStatusBody;
  }
  async function deactivateTenantKillSwitch(token: string): Promise<void> {
    await request(humanApp.getHttpServer() as App)
      .post('/tenants/kill-switch/deactivate')
      .set('Authorization', `Bearer ${token}`)
      .expect(201);
  }

  async function activateAgentKillSwitch(
    token: string,
    agentId: string,
    reason?: string,
  ): Promise<KillSwitchStatusBody> {
    const res = await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/kill-switch`)
      .set('Authorization', `Bearer ${token}`)
      .send(reason ? { reason } : {})
      .expect(201);
    return res.body as KillSwitchStatusBody;
  }
  async function deactivateAgentKillSwitch(
    token: string,
    agentId: string,
  ): Promise<void> {
    await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/kill-switch/deactivate`)
      .set('Authorization', `Bearer ${token}`)
      .expect(201);
  }

  async function activateAgentGroupKillSwitch(
    token: string,
    groupId: string,
    reason?: string,
  ): Promise<KillSwitchStatusBody> {
    const res = await request(humanApp.getHttpServer() as App)
      .post(`/agent-groups/${groupId}/kill-switch`)
      .set('Authorization', `Bearer ${token}`)
      .send(reason ? { reason } : {})
      .expect(201);
    return res.body as KillSwitchStatusBody;
  }
  async function deactivateAgentGroupKillSwitch(
    token: string,
    groupId: string,
  ): Promise<void> {
    await request(humanApp.getHttpServer() as App)
      .post(`/agent-groups/${groupId}/kill-switch/deactivate`)
      .set('Authorization', `Bearer ${token}`)
      .expect(201);
  }

  async function activateToolKillSwitch(
    token: string,
    toolId: string,
    reason?: string,
  ): Promise<KillSwitchStatusBody> {
    const res = await request(humanApp.getHttpServer() as App)
      .post(`/tools/${toolId}/kill-switch`)
      .set('Authorization', `Bearer ${token}`)
      .send(reason ? { reason } : {})
      .expect(201);
    return res.body as KillSwitchStatusBody;
  }
  async function deactivateToolKillSwitch(
    token: string,
    toolId: string,
  ): Promise<void> {
    await request(humanApp.getHttpServer() as App)
      .post(`/tools/${toolId}/kill-switch/deactivate`)
      .set('Authorization', `Bearer ${token}`)
      .expect(201);
  }

  async function activatePlatformKillSwitch(
    token: string,
    reason?: string,
  ): Promise<PlatformKillSwitchStatusBody> {
    const res = await request(humanApp.getHttpServer() as App)
      .post('/kill-switches/platform')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Platform-Operator-Token', PLATFORM_OPERATOR_TOKEN)
      .send(reason ? { reason } : {})
      .expect(201);
    return res.body as PlatformKillSwitchStatusBody;
  }
  /**
   * Test cleanup only: the legacy deactivate route is refused (two-person release through the
   * platform API), so the suite resets the control-DB row itself.
   */
  async function resetPlatformKillSwitch(): Promise<void> {
    await control.platformKillSwitch.updateMany({
      where: { id: 'singleton' },
      data: { active: false },
    });
  }

  interface RawResponse {
    status: number;
    body: unknown;
  }

  function mtlsRequest(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {},
  ): Promise<RawResponse> {
    const bodyText = body !== undefined ? JSON.stringify(body) : undefined;
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: agentMtlsPort,
          path,
          method,
          cert: identity.certificatePem,
          key: identity.privateKeyPem,
          ca: fullCaChainPem,
          rejectUnauthorized: true,
          timeout: 15_000,
          headers: bodyText
            ? {
                'Content-Type': 'application/json',
                Accept: 'application/json, text/event-stream',
                'Content-Length': Buffer.byteLength(bodyText),
                ...extraHeaders,
              }
            : extraHeaders,
        },
        (res) => {
          let data = '';
          res.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
          res.on('end', () => {
            resolve({
              status: res.statusCode ?? 0,
              body: data ? (JSON.parse(data) as unknown) : undefined,
            });
          });
        },
      );
      req.on('error', reject);
      if (bodyText) req.write(bodyText);
      req.end();
    });
  }

  function invokeToolOverMtls(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    body: unknown,
  ): Promise<RawResponse> {
    return mtlsRequest(identity, 'POST', '/agent/v1/tools/invoke', body);
  }

  function pollApprovalOverMtls(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    approvalId: string,
  ): Promise<RawResponse> {
    return mtlsRequest(identity, 'GET', `/agent/v1/approvals/${approvalId}`);
  }

  async function decideApproval(
    approvalId: string,
    decision: 'APPROVE' | 'DENY',
    token: string = adminToken,
  ): Promise<RawResponse> {
    const res = await request(humanApp.getHttpServer() as App)
      .post(`/approvals/${approvalId}/decide`)
      .set('Authorization', `Bearer ${token}`)
      .send({ decision });
    return { status: res.status, body: res.body as unknown };
  }

  interface ApprovalPollBody {
    id: string;
    status: string;
    grantToken?: string;
    grantExpiresAt?: string;
  }

  async function waitForApprovalStatus(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    approvalId: string,
    timeoutMs = 15_000,
  ): Promise<ApprovalPollBody> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const res = await pollApprovalOverMtls(identity, approvalId);
      const body = res.body as ApprovalPollBody;
      if (body.status !== 'PENDING' || Date.now() > deadline) {
        return body;
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
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

    const intermediateCaPath =
      process.env.AGENT_MTLS_CLIENT_CA_PATH ?? 'deploy/openbao/ca-chain.pem';
    fullCaChainPem = readFileSync(intermediateCaPath, 'utf8');

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
            ca: readFileSync(intermediateCaPath),
            requestCert: true,
            rejectUnauthorized: true,
          },
        }),
      );
    await agentMtlsApp.init();
    await agentMtlsApp.getHttpAdapter().getInstance().ready();
    await agentMtlsApp.listen(0, '127.0.0.1');
    const mtlsAddress = agentMtlsApp.getHttpServer().address() as AddressInfo;
    agentMtlsPort = mtlsAddress.port;
    agentMtlsEndpoint = `https://127.0.0.1:${agentMtlsPort}`;

    control = humanApp.get(ControlPrismaService);
    tenantDatabaseManager = humanApp.get(TenantDatabaseManager);
    provisioning = moduleFixture.get(TenantProvisioningService);

    // Real Temporal worker, in-process — see class doc comment and
    // test/approvals.e2e-spec.ts's identical setup. Only test 5 (grant
    // redemption) needs this, but it's cheap to bootstrap once here.
    workerModuleFixture = await Test.createTestingModule({
      imports: [WorkerAppModule],
    }).compile();
    const activities = workerModuleFixture
      .get(ApprovalActivitiesFactory)
      .build();
    const temporalAddress = process.env.TEMPORAL_ADDRESS ?? 'localhost:7233';
    temporalConnection = await NativeConnection.connect({
      address: temporalAddress,
    });
    temporalWorker = await Worker.create({
      connection: temporalConnection,
      namespace: process.env.TEMPORAL_NAMESPACE ?? 'default',
      taskQueue: process.env.TEMPORAL_TASK_QUEUE ?? 'manar-approvals',
      workflowsPath: join(
        process.cwd(),
        'src/temporal/workflows/approval.workflow.ts',
      ),
      activities,
    });
    temporalWorkerRunPromise = temporalWorker.run();

    const first = await provisionTestTenant('t1', ADMIN_USERNAME);
    tenant = first.tenant;
    adminToken = first.token;

    const second = await provisionTestTenant('t2', ADMIN_USERNAME_2);
    tenant2 = second.tenant;
    adminToken2 = second.token;

    // Safety net: force the process-wide platform switch off in case a
    // previously crashed run left it active — see class doc comment.
    await resetPlatformKillSwitch();
  }, 180_000);

  afterAll(async () => {
    // Belt-and-suspenders: never leave the shared, cross-tenant platform
    // switch active for any other concurrently/subsequently running suite.
    await resetPlatformKillSwitch().catch(() => undefined);

    temporalWorker?.shutdown();
    await temporalWorkerRunPromise;
    await temporalConnection?.close();
    await workerModuleFixture?.close();

    await humanApp.close();
    await agentMtlsApp.close();
    if (tenant) await cleanupTenant(tenant);
    if (tenant2) await cleanupTenant(tenant2);
    await control.$disconnect();
  }, 60_000);

  it('1. TENANT kill switch denies a previously-ALLOWed action immediately; deactivating restores it', async () => {
    const agent = await createEnrolledAgent('tenant-scope');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });
    const authorizeRequest = {
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };

    const before = await agent.manar.authorize(authorizeRequest);
    expect(before).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    const activated = await activateTenantKillSwitch(
      adminToken,
      'e2e tenant kill switch test',
    );
    expect(activated.active).toBe(true);
    expect(activated.scope).toBe('TENANT');

    try {
      const during = await agent.manar.authorize(authorizeRequest);
      expect(during.decision).toBe('DENY');
      expect((during as { reason: string }).reason).toBe(
        'tenant_kill_switch_active',
      );
    } finally {
      await deactivateTenantKillSwitch(adminToken);
    }

    const after = await agent.manar.authorize(authorizeRequest);
    expect(after).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  it('2. AGENT kill switch denies a previously-ALLOWed action immediately; deactivating restores it', async () => {
    const agent = await createEnrolledAgent('agent-scope');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });
    const authorizeRequest = {
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };

    const before = await agent.manar.authorize(authorizeRequest);
    expect(before).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    const activated = await activateAgentKillSwitch(adminToken, agent.agentId);
    expect(activated.scope).toBe('AGENT');
    expect(activated.targetId).toBe(agent.agentId);

    const during = await agent.manar.authorize(authorizeRequest);
    expect(during.decision).toBe('DENY');
    expect((during as { reason: string }).reason).toBe(
      'agent_kill_switch_active',
    );

    await deactivateAgentKillSwitch(adminToken, agent.agentId);

    const after = await agent.manar.authorize(authorizeRequest);
    expect(after).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  it('3. AGENT_GROUP kill switch denies a previously-ALLOWed action immediately; deactivating restores it', async () => {
    const agent = await createEnrolledAgent('group-scope');
    const group = await createAgentGroupWithMember(
      tenant.id,
      agent.agentId,
      uniqueSlug('group'),
    );
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });
    const authorizeRequest = {
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };

    const before = await agent.manar.authorize(authorizeRequest);
    expect(before).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    const activated = await activateAgentGroupKillSwitch(adminToken, group.id);
    expect(activated.scope).toBe('AGENT_GROUP');
    expect(activated.targetId).toBe(group.id);

    const during = await agent.manar.authorize(authorizeRequest);
    expect(during.decision).toBe('DENY');
    expect((during as { reason: string }).reason).toBe(
      'agent_group_kill_switch_active',
    );

    await deactivateAgentGroupKillSwitch(adminToken, group.id);

    const after = await agent.manar.authorize(authorizeRequest);
    expect(after).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  it('4. TOOL kill switch denies a previously-ALLOWed action immediately; deactivating restores it', async () => {
    const tool = await registerTool(tenant.id, {
      name: uniqueSlug('tool-scope-tool'),
      baseEndpoint: 'http://127.0.0.1:1/unused',
    });
    const agent = await createEnrolledAgent('tool-scope');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: tool.name, actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
    });
    const authorizeRequest = {
      taskId: task.id,
      toolId: tool.name,
      actionId: 'read',
      resource: 'anything',
    };

    const before = await agent.manar.authorize(authorizeRequest);
    expect(before).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    const activated = await activateToolKillSwitch(adminToken, tool.id);
    expect(activated.scope).toBe('TOOL');
    expect(activated.targetId).toBe(tool.id);

    const during = await agent.manar.authorize(authorizeRequest);
    expect(during.decision).toBe('DENY');
    expect((during as { reason: string }).reason).toBe(
      'tool_kill_switch_active',
    );

    await deactivateToolKillSwitch(adminToken, tool.id);

    const after = await agent.manar.authorize(authorizeRequest);
    expect(after).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  it('5. grant redemption: an already-issued, still-valid AuthorizationGrant becomes unusable the moment a kill switch activates', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool(tenant.id, {
        name: uniqueSlug('grant-redemption-tool'),
        baseEndpoint,
      });
      await registerToolAction(tenant.id, { toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('grant-redemption');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      // First grant: request -> approve -> poll -> USE successfully. "Agent
      // receives usable authority ... successful action."
      const firstInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'grant-redemption-1',
        params: {},
      });
      expect(firstInvoke.status).toBe(202);
      const { approvalId: firstApprovalId } = firstInvoke.body as {
        approvalId: string;
      };
      await decideApproval(firstApprovalId, 'APPROVE');
      const firstPolled = await waitForApprovalStatus(
        agent.identity,
        firstApprovalId,
      );
      expect(firstPolled.status).toBe('APPROVED');
      const firstUse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'grant-redemption-1',
        params: {},
        grantToken: firstPolled.grantToken,
      });
      expect(firstUse.status).toBe(200);
      expect(fixture.requests).toHaveLength(1);

      // Second grant: a *separate* request/approval/grant for the same
      // agent — issued, approved, but deliberately NOT used yet. This is
      // the "still-unexpired, still-unconsumed grant it already has in
      // hand" the design spec's mandatory test names.
      const secondInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'grant-redemption-2',
        params: {},
      });
      expect(secondInvoke.status).toBe(202);
      const { approvalId: secondApprovalId } = secondInvoke.body as {
        approvalId: string;
      };
      await decideApproval(secondApprovalId, 'APPROVE');
      const secondPolled = await waitForApprovalStatus(
        agent.identity,
        secondApprovalId,
      );
      expect(secondPolled.status).toBe('APPROVED');
      const secondGrantToken = secondPolled.grantToken!;

      // Kill switch activated *after* the second grant was already issued.
      await activateAgentKillSwitch(
        adminToken,
        agent.agentId,
        'e2e grant redemption test',
      );

      let deactivated = false;
      try {
        // Retrying with the still-unexpired, still-unconsumed second grant
        // -> denied by the kill switch, never reaches the tool.
        const deniedRetry = await invokeToolOverMtls(agent.identity, {
          taskId: task.id,
          toolId: tool.name,
          actionId: 'lookup',
          resource: 'grant-redemption-2',
          params: {},
          grantToken: secondGrantToken,
        });
        expect(deniedRetry.status).toBe(403);
        expect((deniedRetry.body as { reason: string }).reason).toBe(
          'agent_kill_switch_active',
        );
        expect(fixture.requests).toHaveLength(1); // still just the first, successful call

        // Deactivating restores it — the grant was never consumed (the
        // kill-switch check runs before the atomic consume), so it's
        // usable again once the switch itself is off, proving the switch
        // (and nothing else — not an accidental consume) was the blocker.
        await deactivateAgentKillSwitch(adminToken, agent.agentId);
        deactivated = true;

        const restoredUse = await invokeToolOverMtls(agent.identity, {
          taskId: task.id,
          toolId: tool.name,
          actionId: 'lookup',
          resource: 'grant-redemption-2',
          params: {},
          grantToken: secondGrantToken,
        });
        expect(restoredUse.status).toBe(200);
        expect(fixture.requests).toHaveLength(2);
      } finally {
        if (!deactivated) {
          await deactivateAgentKillSwitch(adminToken, agent.agentId);
        }
      }
    } finally {
      await fixture.stop();
    }
  }, 45_000);

  it('6. scope precision: a kill switch on Agent A does not deny Agent B', async () => {
    const agentA = await createEnrolledAgent('scope-precision-a');
    const agentB = await createEnrolledAgent('scope-precision-b');
    const taskA = await createTask({
      assignedAgentId: agentA.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });
    const taskB = await createTask({
      assignedAgentId: agentB.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    await activateAgentKillSwitch(adminToken, agentA.agentId);
    try {
      const deniedA = await agentA.manar.authorize({
        taskId: taskA.id,
        toolId: 'fs',
        actionId: 'read',
        resource: 'anything',
      });
      expect(deniedA.decision).toBe('DENY');
      expect((deniedA as { reason: string }).reason).toBe(
        'agent_kill_switch_active',
      );

      // Agent B, same tenant, unrelated task -- entirely unaffected.
      const allowedB = await agentB.manar.authorize({
        taskId: taskB.id,
        toolId: 'fs',
        actionId: 'read',
        resource: 'anything',
      });
      expect(allowedB).toEqual<AuthorizeDecision>({
        decision: 'ALLOW',
        decisionId: expect.any(String) as string,
      });
    } finally {
      await deactivateAgentKillSwitch(adminToken, agentA.agentId);
    }
  }, 30_000);

  it('7. platform kill switch denies across every tenant', async () => {
    const agent1 = await createEnrolledAgent('platform-t1', adminToken);
    const task1 = await createTask(
      {
        assignedAgentId: agent1.agentId,
        allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
        allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      },
      adminToken,
    );
    const agent2 = await createEnrolledAgent('platform-t2', adminToken2);
    const task2 = await createTask(
      {
        assignedAgentId: agent2.agentId,
        allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
        allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      },
      adminToken2,
    );

    const request1 = {
      taskId: task1.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };
    const request2 = {
      taskId: task2.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };

    const before1 = await agent1.manar.authorize(request1);
    expect(before1).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
    const before2 = await agent2.manar.authorize(request2);
    expect(before2).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    const activated = await activatePlatformKillSwitch(
      adminToken,
      'e2e platform kill switch test',
    );
    expect(activated.active).toBe(true);

    try {
      const denied1 = await agent1.manar.authorize(request1);
      expect(denied1.decision).toBe('DENY');
      expect((denied1 as { reason: string }).reason).toBe(
        'platform_kill_switch_active',
      );

      const denied2 = await agent2.manar.authorize(request2);
      expect(denied2.decision).toBe('DENY');
      expect((denied2 as { reason: string }).reason).toBe(
        'platform_kill_switch_active',
      );

      // One tenant admin with the operator token can no longer end the stop alone: release is
      // two-person, through the platform API for one named engagement.
      const refused = await request(humanApp.getHttpServer() as App)
        .post('/kill-switches/platform/deactivate')
        .set('Authorization', `Bearer ${adminToken}`)
        .set('X-Platform-Operator-Token', PLATFORM_OPERATOR_TOKEN)
        .expect(403);
      expect((refused.body as { code: string }).code).toBe(
        'platform_release_requires_two_person',
      );
      const still = await agent1.manar.authorize(request1);
      expect((still as { reason: string }).reason).toBe(
        'platform_kill_switch_active',
      );
    } finally {
      await resetPlatformKillSwitch();
    }

    const after1 = await agent1.manar.authorize(request1);
    expect(after1).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
    const after2 = await agent2.manar.authorize(request2);
    expect(after2).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  // ---------------------------------------------------------------------
  // ADR-0009: quarantine and the watcher (Manar's built-in connector).
  // AI may tighten on its own; loosening always needs a human.
  // ---------------------------------------------------------------------

  /** A watcher: an agent whose task grants only the two restriction-only Manar actions. */
  async function createWatcher(
    token: string = adminToken,
    tenantId = tenant.id,
  ) {
    await ensureManarConnector(await tenantDatabaseManager.getClient(tenantId));
    const watcher = await createEnrolledAgent('watcher', token);
    const task = await createTask(
      {
        assignedAgentId: watcher.agentId,
        allowedToolActions: [
          { toolId: 'manar', actionId: 'manar.activity.read' },
          { toolId: 'manar', actionId: 'manar.agent.quarantine' },
        ],
        allowedResourceSelectors: [{ toolId: 'manar', pattern: '*' }],
        riskCeiling: 30,
      },
      token,
    );
    const invoke = (actionId: string, resource: string, params: unknown) =>
      invokeToolOverMtls(watcher.identity, {
        taskId: task.id,
        toolId: 'manar',
        actionId,
        resource,
        params,
      });
    return { ...watcher, taskId: task.id, invoke };
  }

  async function releaseQuarantine(
    agentId: string,
    token: string = adminToken,
  ) {
    return request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/quarantine/release`)
      .set('Authorization', `Bearer ${token}`)
      .send({ note: 'checked by a human' });
  }

  it('8. watcher quarantine: reads metadata only, quarantines without approval, blocks the target, only a human releases', async () => {
    const watcher = await createWatcher();
    const target = await createEnrolledAgent('quarantine-target');
    const task = await createTask({
      assignedAgentId: target.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });
    const SECRET_RESOURCE = `customer-${randomUUID()}`;
    const targetRequest = {
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: SECRET_RESOURCE,
    };
    expect((await target.manar.authorize(targetRequest)).decision).toBe(
      'ALLOW',
    );

    // Activity: metadata and counts, the resource only as a hash.
    const activity = await watcher.invoke('manar.activity.read', 'tenant', {
      windowSeconds: 300,
    });
    expect(activity.status).toBe(200);
    const activityData = (
      activity.body as {
        success: boolean;
        data: { agents: { id: string; decisions: number }[] };
      }
    ).data;
    expect(
      activityData.agents.find((a) => a.id === target.agentId),
    ).toMatchObject({
      decisions: 1,
    });
    expect(JSON.stringify(activity.body)).not.toContain(SECRET_RESOURCE);

    // Quarantine: ALLOW (no approval), recorded as a Decision and audited
    // with the watcher as actor.
    const quarantined = await watcher.invoke(
      'manar.agent.quarantine',
      target.agentId,
      { reason: 'e2e burst', detector: 'deny_burst', evidence: ['d-1'] },
    );
    expect(quarantined.status).toBe(200);
    expect(quarantined.body).toMatchObject({
      success: true,
      data: { result: 'quarantined', agentId: target.agentId },
    });
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const decision = await tenantClient.decision.findFirstOrThrow({
      where: { agentId: watcher.agentId, actionId: 'manar.agent.quarantine' },
    });
    expect(decision.outcome).toBe('ALLOW');
    const quarantineEvents = await tenantClient.auditEvent.findMany({
      where: { eventType: AUDIT_EVENT_TYPES.AGENT_QUARANTINED },
    });
    const ours = quarantineEvents.filter(
      (e) =>
        (e.data as { targetAgentId: string }).targetAgentId === target.agentId,
    );
    expect(ours).toHaveLength(1);
    expect(ours[0]!.actor).toEqual({ type: 'agent', id: watcher.agentId });

    // Idempotent: a second call changes nothing and audits nothing.
    const again = await watcher.invoke(
      'manar.agent.quarantine',
      target.agentId,
      {
        reason: 'again',
      },
    );
    expect(again.body).toMatchObject({
      data: { result: 'already_quarantined' },
    });

    // The target is stopped everywhere, fail closed, but its identity works
    // so it can read why.
    const denied = await target.manar.authorize(targetRequest);
    expect(denied).toMatchObject({
      decision: 'DENY',
      reason: 'agent_quarantined',
    });
    const manifest = await mtlsRequest(
      target.identity,
      'GET',
      `/agent/v1/tasks/${task.id}/tool-manifest`,
    );
    expect(manifest.status).toBe(403);
    expect(manifest.body).toMatchObject({ reason: 'agent_quarantined' });
    expect(
      (await mtlsRequest(target.identity, 'GET', '/agent/v1/whoami')).status,
    ).toBe(200);

    // The watcher cannot loosen anything.
    // (a) no release action exists, and none can be granted.
    const releaseAttempt = await watcher.invoke(
      'manar.agent.release',
      target.agentId,
      {},
    );
    expect(releaseAttempt.status).toBe(403);
    expect(releaseAttempt.body).toMatchObject({ decision: 'DENY' });
    await request(humanApp.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: 'release capability',
        assignedAgentId: watcher.agentId,
        allowedToolActions: [
          { toolId: 'manar', actionId: 'manar.agent.release' },
        ],
        allowedResourceSelectors: [{ toolId: 'manar', pattern: '*' }],
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      })
      .expect(400);
    // (b) its mTLS identity reaches no human route: release, kill-switch
    // deactivation and approval decisions do not exist on the agent listener...
    for (const path of [
      `/agent/v1/agents/${target.agentId}/quarantine/release`,
      `/agents/${target.agentId}/quarantine/release`,
      `/agents/${target.agentId}/kill-switch/deactivate`,
      '/tenants/kill-switch/deactivate',
      `/agent/v1/approvals/${randomUUID()}/decide`,
      `/approvals/${randomUUID()}/decide`,
    ]) {
      expect(
        (await mtlsRequest(watcher.identity, 'POST', path, {})).status,
      ).toBe(404);
    }
    // ...and the human app refuses anything without a human JWT.
    for (const path of [
      `/agents/${target.agentId}/quarantine/release`,
      `/agents/${target.agentId}/kill-switch/deactivate`,
      `/approvals/${randomUUID()}/decide`,
    ]) {
      await request(humanApp.getHttpServer() as App)
        .post(path)
        .send({})
        .expect(401);
    }
    // (c) smuggled params are refused.
    const smuggled = await watcher.invoke(
      'manar.agent.quarantine',
      target.agentId,
      { reason: 'x', active: false },
    );
    expect(smuggled.body).toMatchObject({
      success: false,
      errorMessage: 'invalid_params',
    });
    expect((await target.manar.authorize(targetRequest)).decision).toBe('DENY');

    // A human releases; audited with the human.
    const released = await releaseQuarantine(target.agentId);
    expect(released.status).toBe(201);
    expect(released.body).toMatchObject({
      active: false,
      releasedBy: expect.any(String) as string,
      releaseNote: 'checked by a human',
    });
    const releaseEvent = await tenantClient.auditEvent.findFirstOrThrow({
      where: { eventType: AUDIT_EVENT_TYPES.AGENT_QUARANTINE_RELEASED },
      orderBy: { timestamp: 'desc' },
    });
    expect(releaseEvent.actor).toMatchObject({ type: 'human' });
    expect(releaseEvent.data).toMatchObject({ targetAgentId: target.agentId });
    expect((await target.manar.authorize(targetRequest)).decision).toBe(
      'ALLOW',
    );
    // Nothing left to release.
    expect((await releaseQuarantine(target.agentId)).status).toBe(404);

    // After the release the target's window starts afresh: only the one
    // ALLOW since, none of the denials that led to the quarantine.
    const after = await watcher.invoke('manar.activity.read', 'tenant', {});
    expect(
      (
        after.body as {
          data: {
            agents: { id: string; decisions: number; stopped: number }[];
          };
        }
      ).data.agents.find((a) => a.id === target.agentId),
    ).toMatchObject({ decisions: 1, stopped: 0 });
  }, 60_000);

  it('9. watcher cannot reach another tenant: its agents are not found, not quarantined', async () => {
    const watcher = await createWatcher();
    const foreign = await createEnrolledAgent('foreign-agent', adminToken2);
    const foreignTask = await createTask(
      {
        assignedAgentId: foreign.agentId,
        allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
        allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      },
      adminToken2,
    );
    const foreignRequest = {
      taskId: foreignTask.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };
    expect((await foreign.manar.authorize(foreignRequest)).decision).toBe(
      'ALLOW',
    );

    const attempt = await watcher.invoke(
      'manar.agent.quarantine',
      foreign.agentId,
      {
        reason: 'cross-tenant attempt',
      },
    );
    expect(attempt.body).toMatchObject({
      success: false,
      errorMessage: 'agent_not_found',
    });
    const activity = await watcher.invoke('manar.activity.read', 'tenant', {});
    expect(JSON.stringify(activity.body)).not.toContain(foreign.agentId);
    expect((await foreign.manar.authorize(foreignRequest)).decision).toBe(
      'ALLOW',
    );
  }, 30_000);

  it('10. grant redemption: an approved, unused grant is refused while its agent is quarantined', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const watcher = await createWatcher();
      const tool = await registerTool(tenant.id, {
        name: uniqueSlug('quarantine-redemption-tool'),
        baseEndpoint,
      });
      await registerToolAction(tenant.id, { toolId: tool.id, name: 'lookup' });
      const agent = await createEnrolledAgent('quarantine-redemption');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });
      const call = {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'quarantine-redemption-1',
        params: {},
      };
      const pending = await invokeToolOverMtls(agent.identity, call);
      expect(pending.status).toBe(202);
      const { approvalId } = pending.body as { approvalId: string };
      await decideApproval(approvalId, 'APPROVE');
      const approved = await waitForApprovalStatus(agent.identity, approvalId);
      expect(approved.status).toBe('APPROVED');

      await watcher.invoke('manar.agent.quarantine', agent.agentId, {
        reason: 'e2e redemption',
      });
      const refused = await invokeToolOverMtls(agent.identity, {
        ...call,
        grantToken: approved.grantToken,
      });
      expect(refused.status).toBe(403);
      expect(refused.body).toMatchObject({ reason: 'agent_quarantined' });
      expect(fixture.requests).toHaveLength(0);

      expect((await releaseQuarantine(agent.agentId)).status).toBe(201);
      const used = await invokeToolOverMtls(agent.identity, {
        ...call,
        grantToken: approved.grantToken,
      });
      expect(used.status).toBe(200);
      expect(fixture.requests).toHaveLength(1);
    } finally {
      await fixture.stop();
    }
  }, 45_000);

  it('11. a stopped agent cannot delegate, and its children stop with it (quarantine and AGENT kill switch)', async () => {
    const watcher = await createWatcher();
    const parent = await createEnrolledAgent('deleg-parent');
    const parentTask = await createTask({
      assignedAgentId: parent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });
    const delegate = (slug: string) =>
      mtlsRequest(
        parent.identity,
        'POST',
        `/agent/v1/tasks/${parentTask.id}/delegate`,
        {
          childAgentSlug: shortSlug(slug),
          name: 'child',
          allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
          allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
        },
      );
    // A child delegated before anything happens.
    const delegated = await delegate('child');
    expect(delegated.status).toBe(201);
    const d = delegated.body as {
      childTask: { id: string };
      enrollmentToken: { token: string };
    };
    const child = new ManarAgent({
      endpoint: humanEndpoint,
      mtlsEndpoint: agentMtlsEndpoint,
      identityStore: new FileIdentityStore(
        `/tmp/manar-sdk-test-${randomUUID()}.identity`,
        'test-passphrase-not-for-production',
      ),
    });
    await child.enroll(d.enrollmentToken.token);
    const childRequest = {
      taskId: d.childTask.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };
    expect((await child.authorize(childRequest)).decision).toBe('ALLOW');

    // Quarantine the parent: it cannot delegate, and its existing child stops.
    await watcher.invoke('manar.agent.quarantine', parent.agentId, {
      reason: 'e2e delegation escape',
    });
    const refused = await delegate('escape');
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({
      decision: 'DENY',
      reason: 'agent_quarantined',
    });
    expect(await child.authorize(childRequest)).toMatchObject({
      decision: 'DENY',
      reason: 'ancestor_agent_quarantined',
    });
    expect((await releaseQuarantine(parent.agentId)).status).toBe(201);
    expect((await child.authorize(childRequest)).decision).toBe('ALLOW');

    // Same for an AGENT kill switch on the parent.
    await activateAgentKillSwitch(adminToken, parent.agentId, 'e2e delegation');
    try {
      const killed = await delegate('escape-2');
      expect(killed.status).toBe(403);
      expect(killed.body).toMatchObject({ reason: 'agent_kill_switch_active' });
      expect(await child.authorize(childRequest)).toMatchObject({
        decision: 'DENY',
        reason: 'ancestor_agent_kill_switch_active',
      });
    } finally {
      await deactivateAgentKillSwitch(adminToken, parent.agentId);
    }
    expect((await child.authorize(childRequest)).decision).toBe('ALLOW');
  }, 60_000);

  it('12. a quarantined agent is refused at the LLM proxy and at MCP tools/call', async () => {
    const watcher = await createWatcher();
    const agent = await createEnrolledAgent('quarantine-runtime');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });
    await watcher.invoke('manar.agent.quarantine', agent.agentId, {
      reason: 'e2e runtime',
    });
    try {
      const llm = await mtlsRequest(
        agent.identity,
        'POST',
        '/agent/v1/llm/chat/completions',
        { messages: [{ role: 'user', content: 'hello' }] },
        { 'X-Manar-Task-Id': task.id },
      );
      expect(llm.status).toBe(403);
      expect(llm.body).toMatchObject({
        decision: 'DENY',
        reason: 'agent_quarantined',
      });
      const mcp = await mtlsRequest(
        agent.identity,
        'POST',
        `/agent/v1/tasks/${task.id}/mcp`,
        {
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: {
            name: 'fs__read',
            arguments: { resource: 'anything', params: {} },
          },
        },
      );
      // The MCP door answers a refusal as a tool result, not an HTTP error.
      expect(mcp.status).toBe(200);
      expect(mcp.body).toMatchObject({
        result: {
          isError: true,
          structuredContent: { status: 'DENIED', reason: 'agent_quarantined' },
        },
      });
    } finally {
      await releaseQuarantine(agent.agentId);
    }
  }, 30_000);

  it('13. children stop when their parent agent is stopped any other way: AI system suspended, agent revoked', async () => {
    const http = () => request(humanApp.getHttpServer());
    const parentWithChild = async (label: string) => {
      const parent = await createEnrolledAgent(label);
      const parentTask = await createTask({
        assignedAgentId: parent.agentId,
        allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
        allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      });
      const delegation = await parent.manar.delegateTask(parentTask.id, {
        childAgentSlug: shortSlug(`${label}-c`),
        name: 'child',
        allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
        allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      });
      const child = new ManarAgent({
        endpoint: humanEndpoint,
        mtlsEndpoint: agentMtlsEndpoint,
        identityStore: new FileIdentityStore(
          `/tmp/manar-sdk-test-${randomUUID()}.identity`,
          'test-passphrase-not-for-production',
        ),
      });
      await child.enroll(delegation.enrollmentToken.token);
      const req = {
        taskId: delegation.childTask.id,
        toolId: 'fs',
        actionId: 'read',
        resource: 'anything',
      };
      expect((await child.authorize(req)).decision).toBe('ALLOW');
      return { parent, child, req };
    };

    // (a) The parent's AI system is suspended.
    const a = await parentWithChild('ais-parent');
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const owner = await tenantClient.userProfile.findFirstOrThrow();
    const system = (
      await http()
        .post('/ai-systems')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          slug: shortSlug('ais'),
          name: 'Parent system',
          businessPurpose: 'e2e',
          ownerId: owner.id,
          businessUnit: 'e2e',
          environment: 'DEVELOPMENT',
          riskRationale: 'e2e',
        })
        .expect(201)
    ).body as { id: string };
    await http()
      .post(`/ai-systems/${system.id}/agents`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ agentId: a.parent.agentId })
      .expect(201);
    // REVIEW -> ACTIVE needs a second person.
    const reviewerName = shortSlug('reviewer');
    const reviewerId = await createRealmUser(tenant.keycloakRealm!, {
      username: reviewerName,
      email: `${reviewerName}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm!, reviewerId, 'SECURITY_ADMIN');
    const reviewerToken = await getUserToken({
      realm: tenant.keycloakRealm!,
      clientId: tenant.keycloakClientId!,
      clientSecret: (
        await control.secretReference.findFirstOrThrow({
          where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
        })
      ).reference,
      username: reviewerName,
      password: USER_PASSWORD,
    });
    for (const [toState, token] of [
      ['REVIEW', adminToken],
      ['ACTIVE', reviewerToken],
      ['SUSPENDED', adminToken],
    ] as const) {
      await http()
        .post(`/ai-systems/${system.id}/transitions`)
        .set('Authorization', `Bearer ${token}`)
        .send({ toState, reason: 'e2e' })
        .expect(201);
    }
    expect(await a.child.authorize(a.req)).toMatchObject({
      decision: 'DENY',
      reason: 'ancestor_ai_system_suspended',
    });

    // (b) The parent agent is revoked.
    const b = await parentWithChild('rev-parent');
    await http()
      .post(`/agents/${b.parent.agentId}/revoke`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ reason: 'e2e cascade' })
      .expect(201);
    const denied = await b.child.authorize(b.req);
    expect(denied.decision).toBe('DENY');
    expect(denied).toMatchObject({
      reason: expect.stringMatching(/^ancestor_/) as string,
    });
  }, 60_000);

  it('14. the quarantine cap and idempotency hold under concurrency', async () => {
    const CAP = 5; // default QUARANTINE_MAX_PER_AGENT
    const newAgent = async (label: string) =>
      (
        (
          await request(humanApp.getHttpServer())
            .post('/agents')
            .set('Authorization', `Bearer ${adminToken}`)
            .send({ slug: shortSlug(label), displayName: label })
            .expect(201)
        ).body as { id: string }
      ).id;

    // cap + 3 different targets at once from one watcher: exactly cap land.
    const watcher = await createWatcher();
    const targets = await Promise.all(
      Array.from({ length: CAP + 3 }, (_, i) => newAgent(`cap-${i}`)),
    );
    const results = await Promise.all(
      targets.map((id) =>
        watcher.invoke('manar.agent.quarantine', id, { reason: 'e2e cap' }),
      ),
    );
    const bodies = results.map(
      (r) => r.body as { success: boolean; errorMessage?: string },
    );
    expect(bodies.filter((b) => b.success)).toHaveLength(CAP);
    expect(
      bodies.filter((b) => b.errorMessage === 'quarantine_rate_exceeded'),
    ).toHaveLength(3);
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    expect(
      await tenantClient.agentQuarantine.count({
        where: { quarantinedByAgentId: watcher.agentId, active: true },
      }),
    ).toBe(CAP);

    // Three at once on one target: one quarantine, one audit event.
    const second = await createWatcher();
    const target = await newAgent('same-target');
    const same = await Promise.all(
      [1, 2, 3].map(() =>
        second.invoke('manar.agent.quarantine', target, { reason: 'e2e same' }),
      ),
    );
    const outcomes = same
      .map((r) => (r.body as { data: { result: string } }).data.result)
      .sort();
    expect(outcomes).toEqual([
      'already_quarantined',
      'already_quarantined',
      'quarantined',
    ]);
    const events = await tenantClient.auditEvent.findMany({
      where: { eventType: AUDIT_EVENT_TYPES.AGENT_QUARANTINED },
    });
    expect(
      events.filter(
        (e) => (e.data as { targetAgentId: string }).targetAgentId === target,
      ),
    ).toHaveLength(1);
  }, 60_000);
});
