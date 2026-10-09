import 'dotenv/config';
import * as https from 'node:https';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import type { ConfigService } from '@nestjs/config';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import type { FastifyInstance } from 'fastify';
import request from 'supertest';
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
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import { HANDOVER_TTL_MS, HandoverStore } from '../src/tools/handover.store';
import { AiAdvisoryClient } from '../src/ai-advisory/ai-advisory-client.service';
import type { AppConfig } from '../src/config/env.validation';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import {
  ensureMicrosoftFixtureTools,
  MICROSOFT_DEFENDER_TOOL,
  MICROSOFT_FIXTURE_APP,
  MICROSOFT_FIXTURE_IDS,
  MICROSOFT_GRAPH_TOOL,
  microsoftPolicyContent,
} from '../src/cli/commands/microsoft-fixture-seed';
import { buildMicrosoftFixtureApp } from '../packages/demo-soc-tools/src/microsoft/fixture';
import {
  FIXTURE_GROUP_ID,
  FIXTURE_SECOND_USER_ID,
} from '../packages/demo-soc-tools/src/microsoft/seed-data';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';
import { FakeAnalysisServiceServer } from './support/fake-analysis-service-server';

/**
 * Phase 2 (ADR-0004): an enrolled agent drives the Microsoft catalog
 * through the real pipeline (mTLS -> authorize -> policy -> approval
 * workflow -> grant -> credential broker -> OpenBao -> MicrosoftToolAdapter
 * -> OAuth2 token -> Graph/Defender) against the in-process DEMO FIXTURE.
 * State changes are re-checked on the fixture directly, not trusted from
 * the gateway's answer. This proves Manar's side of the integration; it
 * says nothing about behaviour against a live Microsoft tenant.
 */
describe('Microsoft connector through the gateway (DEMO FIXTURE e2e)', () => {
  let humanApp: NestFastifyApplication;
  let agentMtlsApp: NestFastifyApplication;
  let humanEndpoint: string;
  let agentMtlsPort: number;
  let fullCaChainPem: string;

  let temporalConnection: NativeConnection;
  let temporalWorker: Worker;
  let temporalWorkerRunPromise: Promise<void>;
  let workerModuleFixture: TestingModule;
  let fakeAnalysisServer: FakeAnalysisServiceServer;
  let fixture: FastifyInstance;
  let fixtureBase: string;

  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let ownerToken: string;
  let approverToken: string;
  let otherApproverToken: string;

  const USER_PASSWORD = 'Passw0rd!Test';
  const { userId, machineId, incidentId } = MICROSOFT_FIXTURE_IDS;

  const shortSlug = (label: string) =>
    `msft-${label}-${randomUUID().slice(0, 8)}`;

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

  function buildAiAdvisoryClient(grpcTarget: string): AiAdvisoryClient {
    const values = {
      AI_ADVISORY_GRPC_TARGET: grpcTarget,
      AI_ADVISORY_TIMEOUT_MS: 2000,
      AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 3,
      AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
      AI_ADVISORY_LONGFORM_TIMEOUT_MS: 30_000,
      AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD: 3,
      AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
    };
    const configService = {
      get: (key: string) => (values as Record<string, unknown>)[key],
    } as unknown as ConfigService<AppConfig, true>;
    return new AiAdvisoryClient(configService, control);
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
          timeout: 30_000,
          headers: bodyText
            ? {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(bodyText),
              }
            : undefined,
        },
        (res) => {
          let data = '';
          res.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 0,
              body: data ? (JSON.parse(data) as unknown) : undefined,
            }),
          );
        },
      );
      req.on('error', reject);
      if (bodyText) req.write(bodyText);
      req.end();
    });
  }

  async function fixtureState() {
    const res = await fetch(`${fixtureBase}/microsoft/_fixture/state`);
    return (await res.json()) as {
      users: {
        id: string;
        accountEnabled: boolean;
        sessionsRevokedAt: string | null;
      }[];
      isolatedMachineIds: string[];
    };
  }

  async function fixtureRequests() {
    const res = await fetch(`${fixtureBase}/microsoft/_fixture/requests`);
    return (
      (await res.json()) as { requests: { method: string; path: string }[] }
    ).requests;
  }

  beforeAll(async () => {
    fakeAnalysisServer = new FakeAnalysisServiceServer();
    const analysisTarget = await fakeAnalysisServer.start();

    fixture = buildMicrosoftFixtureApp();
    await fixture.listen({ port: 0, host: '127.0.0.1' });
    fixtureBase = `http://127.0.0.1:${(fixture.server.address() as AddressInfo).port}`;

    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    }).compile();
    humanApp = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await humanApp.init();
    await humanApp.getHttpAdapter().getInstance().ready();
    await humanApp.listen(0, '127.0.0.1');
    humanEndpoint = `http://127.0.0.1:${(humanApp.getHttpServer().address() as AddressInfo).port}`;
    control = humanApp.get(ControlPrismaService);
    tenantDatabaseManager = humanApp.get(TenantDatabaseManager);

    const caPath =
      process.env.AGENT_MTLS_CLIENT_CA_PATH ?? 'deploy/openbao/ca-chain.pem';
    fullCaChainPem = readFileSync(caPath, 'utf8');
    const agentMtlsFixture = await Test.createTestingModule({
      imports: [AgentMtlsAppModule],
    })
      .overrideProvider(AiAdvisoryClient)
      .useValue(buildAiAdvisoryClient(analysisTarget))
      .compile();
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
            ca: readFileSync(caPath),
            requestCert: true,
            rejectUnauthorized: true,
          },
        }),
      );
    await agentMtlsApp.init();
    await agentMtlsApp.getHttpAdapter().getInstance().ready();
    await agentMtlsApp.listen(0, '127.0.0.1');
    agentMtlsPort = (agentMtlsApp.getHttpServer().address() as AddressInfo)
      .port;

    workerModuleFixture = await Test.createTestingModule({
      imports: [WorkerAppModule],
    }).compile();
    temporalConnection = await NativeConnection.connect({
      address: process.env.TEMPORAL_ADDRESS ?? 'localhost:7233',
    });
    temporalWorker = await Worker.create({
      connection: temporalConnection,
      namespace: process.env.TEMPORAL_NAMESPACE ?? 'default',
      taskQueue: process.env.TEMPORAL_TASK_QUEUE ?? 'manar-approvals',
      workflowsPath: join(
        process.cwd(),
        'src/temporal/workflows/approval.workflow.ts',
      ),
      activities: workerModuleFixture.get(ApprovalActivitiesFactory).build(),
    });
    temporalWorkerRunPromise = temporalWorker.run();

    tenant = await moduleFixture
      .get(TenantProvisioningService)
      .provisionTenant({
        slug: shortSlug('tenant'),
        name: 'Microsoft connector e2e',
      });
    const realm = tenant.keycloakRealm!;
    const clientSecret = (
      await control.secretReference.findFirstOrThrow({
        where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
      })
    ).reference;
    const tokenFor = async (role: string) => {
      const username = shortSlug(role.toLowerCase().slice(0, 8));
      const id = await createRealmUser(realm, {
        username,
        email: `${username}@example.test`,
        password: USER_PASSWORD,
      });
      await assignRealmRole(realm, id, role);
      return getUserToken({
        realm,
        clientId: tenant.keycloakClientId!,
        clientSecret,
        username,
        password: USER_PASSWORD,
      });
    };
    ownerToken = await tokenFor('TENANT_OWNER');
    approverToken = await tokenFor('APPROVER');
    otherApproverToken = await tokenFor('APPROVER');
  }, 180_000);

  afterAll(async () => {
    temporalWorker?.shutdown();
    await temporalWorkerRunPromise;
    await temporalConnection?.close();
    await workerModuleFixture?.close();
    await humanApp?.close();
    await agentMtlsApp?.close();
    await fixture?.close();
    await fakeAnalysisServer?.stop();
    if (tenant) await cleanupTenant(tenant);
    await control?.$disconnect();
  }, 60_000);

  /**
   * Catalog, fixture secret, the generated default policy, an enrolled agent
   * and a task with `grants`. `approve` asks, checks nothing reached
   * Microsoft, approves as the approver and returns the grant token and the
   * approval id.
   */
  async function governedAgent(grants: Record<string, unknown>) {
    const http = () => request(humanApp.getHttpServer());

    // ---- Setup: catalog + fixture secret in OpenBao + policy + task ----
    const kvPath = `tools/${shortSlug('ms-fixture')}`;
    await humanApp
      .get(OpenBaoKvClient)
      .writeSecret(kvPath, { value: MICROSOFT_FIXTURE_APP.clientSecret });
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    await ensureMicrosoftFixtureTools(tenantClient, {
      fixtureBaseUrl: fixtureBase,
      kvPath,
    });

    const policy = await http()
      .post('/policies')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        name: `Microsoft Connector Approval Policy ${randomUUID().slice(0, 8)}`,
        description: 'Every Microsoft mutation needs approval.',
        content: microsoftPolicyContent(),
        reason: 'microsoft connector e2e',
      })
      .expect(201);
    const policyBody = policy.body as {
      id: string;
      latestVersion: { id: string };
    };
    await http()
      .post(
        `/policies/${policyBody.id}/versions/${policyBody.latestVersion.id}/publish`,
      )
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(201);

    const agentSlug = shortSlug('agent');
    const agentId = (
      (
        await http()
          .post('/agents')
          .set('Authorization', `Bearer ${ownerToken}`)
          .send({ slug: agentSlug, displayName: 'Microsoft e2e agent' })
          .expect(201)
      ).body as { id: string }
    ).id;
    const enrollmentToken = (
      (
        await http()
          .post(`/agents/${agentId}/enrollment-tokens`)
          .set('Authorization', `Bearer ${ownerToken}`)
          .expect(201)
      ).body as { token: string }
    ).token;
    const identity = await new ManarAgent({
      endpoint: humanEndpoint,
      mtlsEndpoint: `https://127.0.0.1:${agentMtlsPort}`,
      identityStore: new FileIdentityStore(
        `/tmp/manar-sdk-test-${randomUUID()}.identity`,
        'test-passphrase-not-for-production',
      ),
    }).enroll(enrollmentToken);

    const task = (
      await http()
        .post('/tasks')
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({
          name: `Microsoft e2e ${randomUUID().slice(0, 8)}`,
          assignedAgentId: agentId,
          forbiddenActions: [],
          expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
          riskCeiling: 100,
          ...grants,
        })
        .expect(201)
    ).body as { id: string };

    const invoke = (body: Record<string, unknown>) =>
      mtlsRequest(identity, 'POST', '/agent/v1/tools/invoke', {
        taskId: task.id,
        params: {},
        ...body,
      });

    /** Asks, sees APPROVAL_REQUIRED with nothing sent to Microsoft, approves, and returns the grant. */
    async function approve(body: Record<string, unknown>): Promise<string> {
      return (await approval(body)).grantToken;
    }
    async function approval(
      body: Record<string, unknown>,
    ): Promise<{ grantToken: string; approvalId: string }> {
      const before = (await fixtureRequests()).length;
      const pending = await invoke(body);
      expect(pending.status).toBe(202);
      const { approvalId, reason } = pending.body as {
        approvalId: string;
        reason: string;
      };
      expect(reason).toBe('policy_requires_approval');
      expect((await fixtureRequests()).length).toBe(before);

      await http()
        .post(`/approvals/${approvalId}/decide`)
        .set('Authorization', `Bearer ${approverToken}`)
        .send({ decision: 'APPROVE', reason: 'Confirmed compromise (fixture)' })
        .expect(201);
      const deadline = Date.now() + 20_000;
      for (;;) {
        const polled = await mtlsRequest(
          identity,
          'GET',
          `/agent/v1/approvals/${approvalId}`,
        );
        const polledBody = polled.body as {
          status: string;
          grantToken?: string;
        };
        if (polledBody.status === 'APPROVED' && polledBody.grantToken) {
          return { grantToken: polledBody.grantToken, approvalId };
        }
        if (Date.now() > deadline) throw new Error('approval did not resolve');
        await new Promise((r) => setTimeout(r, 250));
      }
    }

    return { http, invoke, approve, approval, task, tenantClient };
  }

  it('reads an incident (ALLOW), then disables a user and isolates a device only after human approval', async () => {
    const { invoke, approve, tenantClient, task } = await governedAgent({
      allowedToolActions: [
        { toolId: MICROSOFT_GRAPH_TOOL, actionId: 'security.incident.get' },
        { toolId: MICROSOFT_GRAPH_TOOL, actionId: 'entra.user.get' },
        { toolId: MICROSOFT_GRAPH_TOOL, actionId: 'entra.user.disable' },
        {
          toolId: MICROSOFT_GRAPH_TOOL,
          actionId: 'entra.user.sessions.revoke',
        },
        {
          toolId: MICROSOFT_DEFENDER_TOOL,
          actionId: 'defender.machine.isolate',
        },
        {
          toolId: MICROSOFT_DEFENDER_TOOL,
          actionId: 'defender.machineaction.list',
        },
      ],
      allowedResourceSelectors: [
        { toolId: MICROSOFT_GRAPH_TOOL, pattern: incidentId },
        { toolId: MICROSOFT_GRAPH_TOOL, pattern: userId },
        { toolId: MICROSOFT_DEFENDER_TOOL, pattern: machineId },
      ],
      forbiddenActions: [],
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    });

    // ---- 1. Read the incident: ALLOW, executed at once ----
    const incident = await invoke({
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'security.incident.get',
      resource: incidentId,
      params: { expandAlerts: true },
    });
    expect(incident.status).toBe(200);
    expect(incident.body).toMatchObject({
      success: true,
      data: { id: incidentId, _dataOrigin: 'DEMO_FIXTURE', alerts: [{}, {}] },
    });

    // ---- 2. A user outside the task's resource selectors: DENY ----
    const outOfScope = await invoke({
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.user.disable',
      resource: FIXTURE_SECOND_USER_ID,
    });
    expect(outOfScope.status).toBe(403);

    // ---- 3. Disable the user: APPROVAL_REQUIRED -> approve -> executed ----
    const disableGrant = await approve({
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.user.disable',
      resource: userId,
    });
    expect(
      (await fixtureState()).users.find((u) => u.id === userId)?.accountEnabled,
    ).toBe(true);
    const disabled = await invoke({
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.user.disable',
      resource: userId,
      grantToken: disableGrant,
    });
    expect(disabled.body).toMatchObject({ success: true });
    expect(
      (await fixtureState()).users.find((u) => u.id === userId)?.accountEnabled,
    ).toBe(false);
    const reread = await invoke({
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.user.get',
      resource: userId,
    });
    expect(reread.body).toMatchObject({ data: { accountEnabled: false } });

    // ---- 4. Isolate the device: APPROVAL_REQUIRED -> approve -> executed ----
    const isolateBody = {
      toolId: MICROSOFT_DEFENDER_TOOL,
      actionId: 'defender.machine.isolate',
      resource: machineId,
      params: {
        comment: 'Credential dumping on fx-ws-042 (fixture incident 4201)',
      },
    };
    const isolateGrant = await approve(isolateBody);
    const isolated = await invoke({ ...isolateBody, grantToken: isolateGrant });
    expect(isolated.body).toMatchObject({
      success: true,
      data: { type: 'Isolate', machineId },
    });
    expect((await fixtureState()).isolatedMachineIds).toEqual([machineId]);
    const actions = await invoke({
      toolId: MICROSOFT_DEFENDER_TOOL,
      actionId: 'defender.machineaction.list',
      resource: machineId,
    });
    expect(actions.body).toMatchObject({
      data: { value: [{ type: 'Isolate', status: 'Succeeded' }] },
    });

    // ---- 5. An approved mutation whose answer is lost: UNKNOWN, sent once ----
    const revokePath = `/graph/v1.0/users/${userId}/revokeSignInSessions`;
    const revokeBody = {
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.user.sessions.revoke',
      resource: userId,
    };
    const revokeGrant = await approve(revokeBody);
    await fetch(`${fixtureBase}/microsoft/_fixture/faults`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method: 'POST', path: revokePath, status: 503 }),
    });
    const revoked = await invoke({ ...revokeBody, grantToken: revokeGrant });
    expect(revoked.body).toMatchObject({
      success: false,
      outcomeUnknown: true,
    });
    expect(
      (await fixtureRequests()).filter((r) => r.path === revokePath),
    ).toHaveLength(1);

    // ---- Records: statuses, audit, and no secret or token anywhere ----
    const invocations = await tenantClient.toolInvocation.findMany({
      where: { taskId: task.id },
    });
    expect(invocations.map((i) => i.status).sort()).toEqual([
      'SUCCESS',
      'SUCCESS',
      'SUCCESS',
      'SUCCESS',
      'SUCCESS',
      'UNKNOWN',
    ]);
    const unknownEvents = await tenantClient.auditEvent.findMany({
      where: { eventType: AUDIT_EVENT_TYPES.TOOL_INVOCATION_OUTCOME_UNKNOWN },
    });
    expect(unknownEvents).toHaveLength(1);
    const auditEvents = await tenantClient.auditEvent.findMany();
    const persisted = JSON.stringify([invocations, auditEvents]);
    expect(persisted).not.toContain(MICROSOFT_FIXTURE_APP.clientSecret);
    expect(persisted).not.toContain('fixture.graph.');
    expect(persisted).not.toContain('fixture.defender.');
  }, 120_000);

  it('helpdesk and joiner/leaver: the temporary password reaches only its approver, once; group change, joiner and leaver need approval', async () => {
    const membership = `${FIXTURE_GROUP_ID}:${FIXTURE_SECOND_USER_ID}`;
    const joiner = 'new.joiner@fixture.example';
    const { invoke, approve, approval, http, tenantClient, task } =
      await governedAgent({
        allowedToolActions: [
          'entra.group.members.list',
          'entra.user.password.reset',
          'entra.group.member.add',
          'entra.user.create',
          'entra.user.offboard',
        ].map((actionId) => ({ toolId: MICROSOFT_GRAPH_TOOL, actionId })),
        allowedResourceSelectors: [
          FIXTURE_GROUP_ID,
          userId,
          membership,
          joiner,
        ].map((pattern) => ({ toolId: MICROSOFT_GRAPH_TOOL, pattern })),
      });
    const sentPasswords = async () =>
      (
        (await (
          await fetch(`${fixtureBase}/microsoft/_fixture/requests`)
        ).json()) as {
          requests: {
            method: string;
            body: { passwordProfile?: { password: string } } | null;
          }[];
        }
      ).requests
        .map((r) => r.body?.passwordProfile?.password)
        .filter((p): p is string => typeof p === 'string');
    const riskOf = async (approvalId: string) =>
      (
        await tenantClient.approvalRequest.findUniqueOrThrow({
          where: { id: approvalId },
        })
      ).riskScore;

    // ---- 1. A read is allowed outright ----
    const listed = await invoke({
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.group.members.list',
      resource: FIXTURE_GROUP_ID,
    });
    expect(listed.body).toMatchObject({
      success: true,
      data: { value: [{ id: userId }] },
    });

    // ---- 2. Password reset: approval, then the agent never sees the password ----
    const reset = {
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.user.password.reset',
      resource: userId,
    };
    const resetApproval = await approval(reset);
    const resetDone = await invoke({
      ...reset,
      grantToken: resetApproval.grantToken,
    });
    expect(resetDone.body).toMatchObject({
      success: true,
      data: { passwordReset: true, forceChangePasswordNextSignIn: true },
    });
    const [password] = await sentPasswords();
    expect(password).toBeDefined();
    expect(JSON.stringify(resetDone.body)).not.toContain(password);
    expect(
      (resetDone.body as { data: { handover: string } }).data.handover,
    ).toContain(resetApproval.approvalId);

    const collect = (token: string) =>
      http()
        .post(`/approvals/${resetApproval.approvalId}/handover`)
        .set('Authorization', `Bearer ${token}`);
    await collect(otherApproverToken).expect(403);
    const collected = await collect(approverToken).expect(200);
    expect(collected.headers['cache-control']).toBe('no-store');
    expect(collected.body).toEqual({
      approvalRequestId: resetApproval.approvalId,
      value: { temporaryPassword: password },
    });
    await collect(approverToken).expect(404);
    // KV v1: the collected value is gone from OpenBao, with no version to undelete.
    const kv = humanApp.get(OpenBaoKvClient);
    const handoverPath = `handover/${tenant.id}/${resetApproval.approvalId}`;
    expect(await kv.readV1(handoverPath)).toBeNull();

    // An uncollected value older than 24 h is deleted by the sweep, for good.
    await kv.writeV1(handoverPath, {
      value: JSON.stringify({ temporaryPassword: 'expired-fixture-value' }),
      createdAt: Date.now() - HANDOVER_TTL_MS - 1,
    });
    expect(await humanApp.get(HandoverStore).sweep()).toBeGreaterThanOrEqual(1);
    expect(await kv.readV1(handoverPath)).toBeNull();
    await collect(approverToken).expect(404);

    // ---- 3. Group change: approval, then executed ----
    const add = {
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.group.member.add',
      resource: membership,
    };
    const added = await invoke({ ...add, grantToken: await approve(add) });
    expect(added.body).toMatchObject({ success: true, data: { added: true } });

    // ---- 4. Joiner: approval at high risk; disabled by default ----
    const create = {
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.user.create',
      resource: joiner,
      params: { displayName: 'New Joiner' },
    };
    const createApproval = await approval(create);
    expect(await riskOf(createApproval.approvalId)).toBeGreaterThanOrEqual(70);
    const created = await invoke({
      ...create,
      grantToken: createApproval.grantToken,
    });
    expect(created.body).toMatchObject({
      success: true,
      data: { userPrincipalName: joiner, accountEnabled: false },
    });
    const joinerPassword = (await sentPasswords()).at(-1);
    const joinerHandover = await http()
      .post(`/approvals/${createApproval.approvalId}/handover`)
      .set('Authorization', `Bearer ${approverToken}`)
      .expect(200);
    expect(joinerHandover.body).toMatchObject({
      value: { temporaryPassword: joinerPassword },
    });

    // ---- 5. Leaver: approval at high risk; disabled, sessions revoked, groups removed ----
    const offboard = {
      toolId: MICROSOFT_GRAPH_TOOL,
      actionId: 'entra.user.offboard',
      resource: userId,
    };
    const offboardApproval = await approval(offboard);
    expect(await riskOf(offboardApproval.approvalId)).toBeGreaterThanOrEqual(
      80,
    );
    const left = await invoke({
      ...offboard,
      grantToken: offboardApproval.grantToken,
    });
    expect(left.body).toMatchObject({
      success: true,
      data: {
        disabled: true,
        sessionsRevoked: true,
        groupsRemoved: [FIXTURE_GROUP_ID],
      },
    });
    const after = (await fixtureState()) as unknown as {
      users: { id: string; accountEnabled: boolean }[];
      groups: { id: string; members: string[] }[];
    };
    expect(after.users.find((u) => u.id === userId)?.accountEnabled).toBe(
      false,
    );
    expect(
      after.groups.find((g) => g.id === FIXTURE_GROUP_ID)?.members,
    ).toEqual([FIXTURE_SECOND_USER_ID]);

    // ---- No temporary password anywhere in Manar's records ----
    const passwords = await sentPasswords();
    expect(passwords).toHaveLength(2);
    const persisted = JSON.stringify([
      await tenantClient.toolInvocation.findMany({
        where: { taskId: task.id },
      }),
      await tenantClient.auditEvent.findMany(),
      await tenantClient.decision.findMany({ where: { taskId: task.id } }),
      await tenantClient.approvalRequest.findMany({
        where: { taskId: task.id },
      }),
    ]);
    for (const p of passwords) expect(persisted).not.toContain(p);
    expect(persisted).toContain('approval.handover_collected');
  }, 120_000);
});
