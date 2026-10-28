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
import type { AgentIdentity } from '@manar/sdk-node';
import { AppModule } from '../src/app.module';
import { AgentMtlsAppModule } from '../src/agent-mtls/agent-mtls-app.module';
import { WorkerAppModule } from '../src/temporal/worker-app.module';
import { ApprovalActivitiesFactory } from '../src/temporal/activities/approval.activities';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { AuditService } from '../src/audit/audit.service';
import { AuditCheckpointService } from '../src/audit/checkpoint/audit-checkpoint.service';
import type { AuditEventProof } from '../src/audit/checkpoint/audit-proof.service';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { verifyInclusion } from '../src/audit/merkle';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';
import { HttpFixtureServer } from './support/http-fixture-server';

/**
 * Phase 9a's retrofit-point tests: every mandatory scenario from the design
 * spec's "Testing" section that requires exercising a real API path (not
 * calling `AuditService` directly) — see docs/audit-chain.md. Boots both
 * Nest applications plus a real in-process Temporal worker, exactly like
 * `test/approvals.e2e-spec.ts` — the same "boot the real thing in-process
 * for test convenience" posture that suite already establishes.
 */
describe('Audit retrofit points (e2e)', () => {
  let humanApp: NestFastifyApplication;
  let agentMtlsApp: NestFastifyApplication;
  let humanEndpoint: string;
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
  let auditorToken: string;
  let noAuditRoleToken: string;

  const ADMIN_USERNAME = `audit-admin-${randomUUID().slice(0, 8)}`;
  const AUDITOR_USERNAME = `audit-auditor-${randomUUID().slice(0, 8)}`;
  const PLAIN_USERNAME = `audit-plain-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `audit-${label}-${randomUUID().slice(0, 8)}`;
  }
  function shortSlug(label: string): string {
    return `adt-${label}-${randomUUID().slice(0, 8)}`;
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

  /** Every `AuditEvent` of a given `eventType`, oldest first — the assertion helper every scenario below uses. */
  async function eventsOfType(eventType: string) {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.auditEvent.findMany({
      where: { eventType },
      orderBy: { sequence: 'asc' },
    });
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
      mtlsEndpoint: `https://127.0.0.1:${agentMtlsPort}`,
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
    forbiddenActions?: GrantInput[];
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
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        riskCeiling: input.riskCeiling,
      })
      .expect(201);
    return response.body as { id: string; status: string; expiresAt: string };
  }

  async function registerTool(input: {
    name: string;
    baseEndpoint: string;
    credentialReference: { provider: 'ENV'; reference: string };
  }): Promise<{ id: string; name: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.tool.create({
      data: {
        name: input.name,
        type: 'TEST',
        baseEndpoint: input.baseEndpoint,
        protocol: 'HTTP',
        credentialReference: input.credentialReference,
        enabled: true,
      },
    });
  }

  async function registerToolAction(input: {
    toolId: string;
    name: string;
    riskBaseScore?: number;
  }): Promise<{ id: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.toolAction.create({
      data: {
        toolId: input.toolId,
        name: input.name,
        riskBaseScore: input.riskBaseScore ?? 10,
        mutating: false,
        destructive: false,
      },
    });
  }

  function authorizeOverMtls(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    body: unknown,
  ) {
    return httpsJsonRequest('/agent/v1/authorize', identity, body);
  }

  function invokeToolOverMtls(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    body: unknown,
  ) {
    return httpsJsonRequest('/agent/v1/tools/invoke', identity, body);
  }

  function pollApprovalOverMtls(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    approvalId: string,
  ) {
    return httpsGetRequest(`/agent/v1/approvals/${approvalId}`, identity);
  }

  interface HttpResult {
    status: number;
    body: unknown;
  }

  function httpsJsonRequest(
    path: string,
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    body: unknown,
  ): Promise<HttpResult> {
    const bodyText = JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: agentMtlsPort,
          path,
          method: 'POST',
          cert: identity.certificatePem,
          key: identity.privateKeyPem,
          ca: fullCaChainPem,
          rejectUnauthorized: true,
          timeout: 15_000,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(bodyText),
          },
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
      req.write(bodyText);
      req.end();
    });
  }

  function httpsGetRequest(
    path: string,
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
  ): Promise<HttpResult> {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: agentMtlsPort,
          path,
          method: 'GET',
          cert: identity.certificatePem,
          key: identity.privateKeyPem,
          ca: fullCaChainPem,
          rejectUnauthorized: true,
          timeout: 15_000,
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
      req.end();
    });
  }

  async function pollUntilApproved(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    approvalId: string,
  ): Promise<{ status: string; grantToken?: string }> {
    for (let i = 0; i < 40; i += 1) {
      const res = await pollApprovalOverMtls(identity, approvalId);
      const body = res.body as { status: string; grantToken?: string };
      if (body.status !== 'PENDING') return body;
      await new Promise((r) => setTimeout(r, 250));
    }
    throw new Error(`ApprovalRequest "${approvalId}" never left PENDING`);
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

    control = humanApp.get(ControlPrismaService);
    tenantDatabaseManager = humanApp.get(TenantDatabaseManager);
    provisioning = moduleFixture.get(TenantProvisioningService);

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

    tenant = await provisioning.provisionTenant({
      slug: shortSlug('t'),
      name: 'Audit Retrofit Test Tenant',
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
    // Covers /agents, /tasks, /policies, /approvals/:id/decide, AND
    // /audit/verify in one token.
    await assignRealmRole(tenant.keycloakRealm, adminUserId, 'SECURITY_ADMIN');
    adminToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username: ADMIN_USERNAME,
      password: USER_PASSWORD,
    });

    // A user with ONLY AUDITOR — proves that role alone (not merely
    // SECURITY_ADMIN, which adminToken above already has) grants
    // GET /audit/verify access.
    const auditorUserId = await createRealmUser(tenant.keycloakRealm, {
      username: AUDITOR_USERNAME,
      email: `${AUDITOR_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm, auditorUserId, 'AUDITOR');
    auditorToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username: AUDITOR_USERNAME,
      password: USER_PASSWORD,
    });

    // A user with none of AUDITOR/SECURITY_ADMIN/TENANT_OWNER — proves the
    // endpoint actually rejects a caller without one of those roles.
    const plainUserId = await createRealmUser(tenant.keycloakRealm, {
      username: PLAIN_USERNAME,
      email: `${PLAIN_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm, plainUserId, 'DEVELOPER');
    noAuditRoleToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username: PLAIN_USERNAME,
      password: USER_PASSWORD,
    });
  }, 180_000);

  afterAll(async () => {
    temporalWorker?.shutdown();
    await temporalWorkerRunPromise;
    await temporalConnection?.close();
    await workerModuleFixture?.close();

    await humanApp.close();
    await agentMtlsApp.close();
    if (tenant) await cleanupTenant(tenant);
    await control.$disconnect();
  }, 60_000);

  it('1. agent enrollment success produces agent.enrolled; reusing the same token produces agent.enrollment_failed', async () => {
    const slug = uniqueSlug('enroll');
    const createResponse = await request(humanApp.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ slug, displayName: `Enroll test ${slug}` })
      .expect(201);
    const agentId = (createResponse.body as { id: string }).id;

    const tokenResponse = await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/enrollment-tokens`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(201);
    const rawToken = (tokenResponse.body as { token: string }).token;

    const identityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase',
    );
    const manar = new ManarAgent({
      endpoint: humanEndpoint,
      mtlsEndpoint: `https://127.0.0.1:${agentMtlsPort}`,
      identityStore,
    });
    await manar.enroll(rawToken);

    const enrolledEvents = await eventsOfType(AUDIT_EVENT_TYPES.AGENT_ENROLLED);
    const match = enrolledEvents.find(
      (e) => (e.data as { agentId?: string }).agentId === agentId,
    );
    expect(match).toBeDefined();
    expect(match?.actor).toEqual({ type: 'agent', id: agentId });

    // Reusing the already-consumed token fails, and is itself audited.
    const secondIdentityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase',
    );
    const secondManar = new ManarAgent({
      endpoint: humanEndpoint,
      mtlsEndpoint: `https://127.0.0.1:${agentMtlsPort}`,
      identityStore: secondIdentityStore,
    });
    await expect(secondManar.enroll(rawToken)).rejects.toThrow();

    const failedEvents = await eventsOfType(
      AUDIT_EVENT_TYPES.AGENT_ENROLLMENT_FAILED,
    );
    const failedMatch = failedEvents.find(
      (e) =>
        e.actor &&
        (e.actor as { id?: string }).id === agentId &&
        (e.data as { reason?: string }).reason === 'used',
    );
    expect(failedMatch).toBeDefined();
  }, 60_000);

  it('2. agent revocation produces agent.revoked', async () => {
    const agent = await createEnrolledAgent('revoke');

    await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agent.agentId}/revoke`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ reason: 'audit-retrofit-test' })
      .expect(201);

    const revokedEvents = await eventsOfType(AUDIT_EVENT_TYPES.AGENT_REVOKED);
    const match = revokedEvents.find(
      (e) => (e.data as { agentId?: string }).agentId === agent.agentId,
    );
    expect(match).toBeDefined();
    expect((match?.data as { reason?: string }).reason).toBe(
      'audit-retrofit-test',
    );
  }, 30_000);

  it('3. task creation and task revocation produce task.created and task.revoked', async () => {
    const agent = await createEnrolledAgent('task-crud');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'auditgw', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'auditgw', pattern: '*' }],
    });

    const createdEvents = await eventsOfType(AUDIT_EVENT_TYPES.TASK_CREATED);
    const createdMatch = createdEvents.find(
      (e) => (e.data as { taskId?: string }).taskId === task.id,
    );
    expect(createdMatch).toBeDefined();
    expect(
      (createdMatch?.data as { assignedAgentId?: string }).assignedAgentId,
    ).toBe(agent.agentId);

    await request(humanApp.getHttpServer() as App)
      .post(`/tasks/${task.id}/revoke`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ reason: 'audit-retrofit-test' })
      .expect(201);

    const revokedEvents = await eventsOfType(AUDIT_EVENT_TYPES.TASK_REVOKED);
    const revokedMatch = revokedEvents.find(
      (e) => (e.data as { taskId?: string }).taskId === task.id,
    );
    expect(revokedMatch).toBeDefined();
  }, 30_000);

  it('4. task delegation produces task.delegated, attributed to the delegating agent', async () => {
    const parentAgent = await createEnrolledAgent('delegate-parent');
    const parentTask = await createTask({
      assignedAgentId: parentAgent.agentId,
      allowedToolActions: [{ toolId: 'auditgw', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'auditgw', pattern: '*' }],
    });

    const delegation = await parentAgent.manar.delegateTask(parentTask.id, {
      childAgentSlug: uniqueSlug('delegate-child'),
      name: 'Delegated audit test task',
      allowedToolActions: [{ toolId: 'auditgw', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'auditgw', pattern: '*' }],
    });

    const delegatedEvents = await eventsOfType(
      AUDIT_EVENT_TYPES.TASK_DELEGATED,
    );
    const match = delegatedEvents.find(
      (e) =>
        (e.data as { childTaskId?: string }).childTaskId ===
        delegation.childTask.id,
    );
    expect(match).toBeDefined();
    expect(match?.actor).toEqual({ type: 'agent', id: parentAgent.agentId });
    expect((match?.data as { parentTaskId?: string }).parentTaskId).toBe(
      parentTask.id,
    );
  }, 30_000);

  it('5. authorization DENY (forbidden_action) and ALLOW both produce the matching AuditEvent with the real reason in data', async () => {
    const agent = await createEnrolledAgent('authz');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [
        { toolId: 'auditgw', actionId: 'read' },
        { toolId: 'auditgw', actionId: 'blocked' },
      ],
      allowedResourceSelectors: [{ toolId: 'auditgw', pattern: '*' }],
      forbiddenActions: [{ toolId: 'auditgw', actionId: 'blocked' }],
    });

    const denyResponse = await authorizeOverMtls(agent.identity, {
      taskId: task.id,
      toolId: 'auditgw',
      actionId: 'blocked',
      resource: 'res-1',
    });
    expect((denyResponse.body as { decision: string }).decision).toBe('DENY');

    const deniedEvents = await eventsOfType(
      AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED,
    );
    const deniedMatch = deniedEvents.find(
      (e) =>
        (e.data as { taskId?: string; actionId?: string }).taskId === task.id &&
        (e.data as { actionId?: string }).actionId === 'blocked',
    );
    expect(deniedMatch).toBeDefined();
    expect((deniedMatch?.data as { reason?: string }).reason).toBe(
      'forbidden_action',
    );
    expect(deniedMatch?.actor).toEqual({ type: 'agent', id: agent.agentId });

    const allowResponse = await authorizeOverMtls(agent.identity, {
      taskId: task.id,
      toolId: 'auditgw',
      actionId: 'read',
      resource: 'res-2',
    });
    expect((allowResponse.body as { decision: string }).decision).toBe('ALLOW');

    const allowedEvents = await eventsOfType(
      AUDIT_EVENT_TYPES.AUTHORIZATION_ALLOWED,
    );
    const allowedMatch = allowedEvents.find(
      (e) =>
        (e.data as { taskId?: string; actionId?: string }).taskId === task.id &&
        (e.data as { actionId?: string }).actionId === 'read',
    );
    expect(allowedMatch).toBeDefined();
  }, 30_000);

  it('6-9. tool invocation success/failure, approval requested/approved/grant_issued/denied, and credential secrecy in AuditEvent.data', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const credentialValue = `env-cred-${randomUUID()}`;
      process.env.AUDIT_RETROFIT_TEST_CRED = credentialValue;

      const tool = await registerTool({
        name: uniqueSlug('tool'),
        baseEndpoint,
        credentialReference: {
          provider: 'ENV',
          reference: 'AUDIT_RETROFIT_TEST_CRED',
        },
      });
      await registerToolAction({
        toolId: tool.id,
        name: 'safe-op',
        riskBaseScore: 5,
      });
      await registerToolAction({
        toolId: tool.id,
        name: 'risky-op',
        riskBaseScore: 90, // pushes finalRiskScore above the task's default riskCeiling (20) -- see docs/policy-model.md.
      });

      const agent = await createEnrolledAgent('tool-invoke');
      const safeTask = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'safe-op' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
      });

      // --- Tool invocation success ---
      fixture.setResponse({ status: 200, body: { ok: true } });
      const successResponse = await invokeToolOverMtls(agent.identity, {
        taskId: safeTask.id,
        toolId: tool.name,
        actionId: 'safe-op',
        resource: 'res-success',
        params: {},
      });
      expect(successResponse.status).toBe(200);
      expect((successResponse.body as { success: boolean }).success).toBe(true);

      const startedEvents = await eventsOfType(
        AUDIT_EVENT_TYPES.TOOL_INVOCATION_STARTED,
      );
      expect(
        startedEvents.some(
          (e) => (e.data as { resource?: string }).resource === 'res-success',
        ),
      ).toBe(true);

      const completedEvents = await eventsOfType(
        AUDIT_EVENT_TYPES.TOOL_INVOCATION_COMPLETED,
      );
      const completedMatch = completedEvents.find(
        (e) => (e.data as { resource?: string }).resource === 'res-success',
      );
      expect(completedMatch).toBeDefined();
      expect((completedMatch?.data as { status?: string }).status).toBe(
        'SUCCESS',
      );

      // --- Tool invocation failure ---
      fixture.setResponse({ status: 503, body: { error: 'unavailable' } });
      const failureResponse = await invokeToolOverMtls(agent.identity, {
        taskId: safeTask.id,
        toolId: tool.name,
        actionId: 'safe-op',
        resource: 'res-failure',
        params: {},
      });
      expect(failureResponse.status).toBe(200); // gateway succeeded; the TOOL call failed
      expect((failureResponse.body as { success: boolean }).success).toBe(
        false,
      );

      const failedEvents = await eventsOfType(
        AUDIT_EVENT_TYPES.TOOL_INVOCATION_FAILED,
      );
      const failedMatch = failedEvents.find(
        (e) => (e.data as { resource?: string }).resource === 'res-failure',
      );
      expect(failedMatch).toBeDefined();
      expect((failedMatch?.data as { status?: string }).status).toBe('FAILURE');

      // --- Credential secrecy: grep every tool.invocation.* AuditEvent's
      // stored `data`, not just this test's own two matches, for the raw
      // credential value -- proven, not asserted (Section 35's precedent
      // in test/tool-gateway.e2e-spec.ts, extended to the audit chain).
      const allInvocationEvents = [
        ...startedEvents,
        ...completedEvents,
        ...failedEvents,
      ];
      for (const event of allInvocationEvents) {
        const serialized = JSON.stringify(event.data);
        expect(serialized).not.toContain(credentialValue);
      }
      // Also grep the FULL AuditEvent row (every field, not just `data`) —
      // belt and suspenders.
      for (const event of allInvocationEvents) {
        expect(JSON.stringify(event)).not.toContain(credentialValue);
      }

      // --- Approval requested / approved / grant_issued ---
      const riskyTask = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'risky-op' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
      });

      fixture.setResponse({ status: 200, body: { ok: true } });
      const pendingResponse = await invokeToolOverMtls(agent.identity, {
        taskId: riskyTask.id,
        toolId: tool.name,
        actionId: 'risky-op',
        resource: 'res-approve-me',
        params: {},
      });
      expect(pendingResponse.status).toBe(202);
      const approvalId = (pendingResponse.body as { approvalId: string })
        .approvalId;
      expect(approvalId).toBeTruthy();

      const pendingApprovalEvents = await eventsOfType(
        AUDIT_EVENT_TYPES.AUTHORIZATION_PENDING_APPROVAL,
      );
      expect(
        pendingApprovalEvents.some(
          (e) =>
            (e.data as { resource?: string }).resource === 'res-approve-me',
        ),
      ).toBe(true);

      const requestedEvents = await eventsOfType(
        AUDIT_EVENT_TYPES.APPROVAL_REQUESTED,
      );
      const requestedMatch = requestedEvents.find(
        (e) =>
          (e.data as { approvalRequestId?: string }).approvalRequestId ===
          approvalId,
      );
      expect(requestedMatch).toBeDefined();

      await request(humanApp.getHttpServer() as App)
        .post(`/approvals/${approvalId}/decide`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ decision: 'APPROVE', reason: 'audit-retrofit-test' })
        .expect(201);

      const approved = await pollUntilApproved(agent.identity, approvalId);
      expect(approved.status).toBe('APPROVED');
      expect(approved.grantToken).toBeTruthy();

      const approvedEvents = await eventsOfType(
        AUDIT_EVENT_TYPES.APPROVAL_APPROVED,
      );
      expect(
        approvedEvents.some(
          (e) =>
            (e.data as { approvalRequestId?: string }).approvalRequestId ===
            approvalId,
        ),
      ).toBe(true);

      const grantIssuedEvents = await eventsOfType(
        AUDIT_EVENT_TYPES.APPROVAL_GRANT_ISSUED,
      );
      const grantMatch = grantIssuedEvents.find(
        (e) =>
          (e.data as { approvalRequestId?: string }).approvalRequestId ===
          approvalId,
      );
      expect(grantMatch).toBeDefined();
      expect(grantMatch?.actor).toEqual({
        type: 'system',
        id: 'system:approval-workflow',
      });
      // Never the signed token itself.
      expect(JSON.stringify(grantMatch)).not.toContain(
        approved.grantToken as string,
      );

      // --- Approval denied ---
      const pendingResponse2 = await invokeToolOverMtls(agent.identity, {
        taskId: riskyTask.id,
        toolId: tool.name,
        actionId: 'risky-op',
        resource: 'res-deny-me',
        params: {},
      });
      expect(pendingResponse2.status).toBe(202);
      const approvalId2 = (pendingResponse2.body as { approvalId: string })
        .approvalId;

      await request(humanApp.getHttpServer() as App)
        .post(`/approvals/${approvalId2}/decide`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ decision: 'DENY', reason: 'audit-retrofit-test-deny' })
        .expect(201);

      const denied = await pollUntilApproved(agent.identity, approvalId2);
      expect(denied.status).toBe('DENIED');

      const deniedApprovalEvents = await eventsOfType(
        AUDIT_EVENT_TYPES.APPROVAL_DENIED,
      );
      const deniedApprovalMatch = deniedApprovalEvents.find(
        (e) =>
          (e.data as { approvalRequestId?: string }).approvalRequestId ===
          approvalId2,
      );
      expect(deniedApprovalMatch).toBeDefined();
      expect(
        (deniedApprovalMatch?.data as { decision?: string }).decision,
      ).toBe('DENY');

      delete process.env.AUDIT_RETROFIT_TEST_CRED;
    } finally {
      await fixture.stop();
    }
  }, 90_000);

  it('10. policy publish produces policy.published', async () => {
    const name = uniqueSlug('policy');
    const createResponse = await request(humanApp.getHttpServer() as App)
      .post('/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name,
        content: {
          rules: [{ toolId: 'auditgw', actionId: 'read', effect: 'ALLOW' }],
        },
      })
      .expect(201);
    const body = createResponse.body as {
      id: string;
      latestVersion: { id: string };
    };

    await request(humanApp.getHttpServer() as App)
      .post(`/policies/${body.id}/versions/${body.latestVersion.id}/publish`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(201);

    const publishedEvents = await eventsOfType(
      AUDIT_EVENT_TYPES.POLICY_PUBLISHED,
    );
    const match = publishedEvents.find(
      (e) => (e.data as { policyId?: string }).policyId === body.id,
    );
    expect(match).toBeDefined();
  }, 30_000);

  it('11. GET /audit/verify is reachable with AUDITOR alone and rejects a caller with none of the three roles', async () => {
    const auditorResponse = await request(humanApp.getHttpServer() as App)
      .get('/audit/verify')
      .set('Authorization', `Bearer ${auditorToken}`)
      .expect(200);
    expect((auditorResponse.body as { valid: boolean }).valid).toBe(true);

    await request(humanApp.getHttpServer() as App)
      .get('/audit/verify')
      .set('Authorization', `Bearer ${noAuditRoleToken}`)
      .expect(403);
  }, 30_000);

  it('11b. audit proofs and the SEAL public key: same roles, 404/409 before 200', async () => {
    const server = humanApp.getHttpServer() as App;
    const client = await humanApp
      .get(TenantDatabaseManager)
      .getClient(tenant.id);
    const event = await humanApp.get(AuditService).record(client, tenant.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'system', id: 'system:proof-e2e' },
      data: {},
    });

    await request(server)
      .get(`/audit/events/${event.id}/proof`)
      .set('Authorization', `Bearer ${noAuditRoleToken}`)
      .expect(403);
    await request(server)
      .get(`/audit/events/${randomUUID()}/proof`)
      .set('Authorization', `Bearer ${auditorToken}`)
      .expect(404);

    // This app runs no worker scheduler, so nothing is sealed yet.
    const pending = await request(server)
      .get(`/audit/events/${event.id}/proof`)
      .set('Authorization', `Bearer ${auditorToken}`)
      .expect(409);
    expect(JSON.stringify(pending.body)).toContain(
      'audit_event_not_checkpointed',
    );

    await humanApp
      .get(AuditCheckpointService)
      .createCheckpoint(client, tenant.id);

    const proof = await request(server)
      .get(`/audit/events/${event.id}/proof`)
      .set('Authorization', `Bearer ${auditorToken}`)
      .expect(200);
    const key = await request(server)
      .get('/audit/checkpoints/public-key')
      .set('Authorization', `Bearer ${auditorToken}`)
      .expect(200);
    const body = proof.body as AuditEventProof;
    const publicKey = key.body as { keyId: string; publicKeyPem: string };
    expect(verifyInclusion(body.leaf, body.proof, body.root)).toBe(true);
    expect(body.checkpoint.keyId).toBe(publicKey.keyId);
    expect(
      CheckpointSigner.verify(
        body.checkpoint.checkpointHash,
        body.checkpoint.signature,
        publicKey.publicKeyPem,
      ),
    ).toBe(true);
    await request(server)
      .get('/audit/checkpoints/public-key')
      .set('Authorization', `Bearer ${noAuditRoleToken}`)
      .expect(403);
  }, 30_000);
});
