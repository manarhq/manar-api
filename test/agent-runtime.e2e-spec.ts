import 'dotenv/config';
import { vi } from 'vitest';

// ConfigModule reads the environment when AppConfigModule is imported, so the
// LLM settings must be in place before the imports below (vi.hoisted runs first).
const LLM_ENV = vi.hoisted(() => {
  const port = 40_000 + Math.floor(Math.random() * 10_000);
  process.env.LLM_PROVIDER = 'ollama';
  process.env.LLM_OLLAMA_BASE_URL = `http://127.0.0.1:${port}/v1`;
  process.env.LLM_MODEL = 'fixture-model';
  process.env.LLM_TASK_TOKEN_BUDGET = '150';
  return { port, budget: 150 };
});
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
  socAgentTaskGrants,
} from '../src/cli/commands/microsoft-fixture-seed';
import { buildMicrosoftFixtureApp } from '../packages/demo-soc-tools/src/microsoft/fixture';
import { FIXTURE_SECOND_USER_ID } from '../packages/demo-soc-tools/src/microsoft/seed-data';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';
import { FakeAnalysisServiceServer } from './support/fake-analysis-service-server';
import { FakeOpenAiUpstream } from './support/fake-openai-upstream';

/**
 * ADR-0002: the agent runtime surface on the mTLS listener, end to end
 * against the Microsoft DEMO FIXTURE and a fake OpenAI-compatible upstream
 * (no Ollama in CI): the per-task tool manifest, the governed MCP server
 * (tools/list, tools/call for ALLOW / PENDING -> approve -> poll -> redeem /
 * DENY) and the LLM proxy (DLP floor, budget, audit, ownership).
 */
describe('Agent runtime: manifest, governed MCP server, LLM proxy (e2e)', () => {
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
  let upstream: FakeOpenAiUpstream;

  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let ownerToken: string;
  let approverToken: string;

  const USER_PASSWORD = 'Passw0rd!Test';
  const BUDGET = LLM_ENV.budget;
  const { userId, machineId, incidentId } = MICROSOFT_FIXTURE_IDS;

  const shortSlug = (label: string) =>
    `rt-${label}-${randomUUID().slice(0, 8)}`;

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
    headers: Record<string, string | string[] | undefined>;
    body: unknown;
  }

  function mtlsRequest(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    method: 'GET' | 'POST' | 'DELETE',
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
          timeout: 30_000,
          headers: {
            ...extraHeaders,
            ...(bodyText
              ? {
                  'Content-Type': 'application/json',
                  'Content-Length': Buffer.byteLength(bodyText),
                }
              : {}),
          },
        },
        (res) => {
          let data = '';
          res.on('data', (chunk: Buffer) => (data += chunk.toString('utf8')));
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
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
    upstream = new FakeOpenAiUpstream();
    await upstream.start(LLM_ENV.port);
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
    await upstream?.stop();
    if (tenant) await cleanupTenant(tenant);
    await control?.$disconnect();
  }, 60_000);

  type Identity = Pick<
    AgentIdentity,
    'certificatePem' | 'caChainPem' | 'privateKeyPem'
  >;
  let agentA: Identity;
  let agentB: Identity;
  let agentAId: string;
  let task: { id: string };
  let budgetTask: { id: string };
  let tenantClientRef: Awaited<ReturnType<TenantDatabaseManager['getClient']>>;

  const http = () => request(humanApp.getHttpServer());

  async function createTask(body: Record<string, unknown>) {
    return (
      await http()
        .post('/tasks')
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({
          name: `runtime e2e ${randomUUID().slice(0, 8)}`,
          assignedAgentId: agentAId,
          forbiddenActions: [],
          expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
          riskCeiling: 50,
          ...body,
        })
        .expect(201)
    ).body as { id: string };
  }

  async function enrollAgent(label: string) {
    const id = (
      (
        await http()
          .post('/agents')
          .set('Authorization', `Bearer ${ownerToken}`)
          .send({ slug: shortSlug(label), displayName: `Runtime ${label}` })
          .expect(201)
      ).body as { id: string }
    ).id;
    const token = (
      (
        await http()
          .post(`/agents/${id}/enrollment-tokens`)
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
    }).enroll(token);
    return { id, identity };
  }

  const MCP_HEADERS = { Accept: 'application/json, text/event-stream' };
  let rpcId = 0;
  async function mcp(
    identity: Identity,
    taskId: string,
    method: string,
    params?: unknown,
  ) {
    rpcId += 1;
    return mtlsRequest(
      identity,
      'POST',
      `/agent/v1/tasks/${taskId}/mcp`,
      { jsonrpc: '2.0', id: rpcId, method, ...(params ? { params } : {}) },
      MCP_HEADERS,
    );
  }
  async function callTool(
    name: string,
    args: Record<string, unknown>,
    on: { identity?: Identity; taskId?: string } = {},
  ) {
    const res = await mcp(
      on.identity ?? agentA,
      on.taskId ?? task.id,
      'tools/call',
      {
        name,
        arguments: args,
      },
    );
    expect(res.status).toBe(200);
    return (
      res.body as {
        result: {
          isError: boolean;
          structuredContent: Record<string, unknown>;
        };
      }
    ).result;
  }

  const chat = (
    identity: Identity,
    taskId: string | undefined,
    content: string,
  ) =>
    mtlsRequest(
      identity,
      'POST',
      '/agent/v1/llm/chat/completions',
      { model: 'ignored', messages: [{ role: 'user', content }] },
      taskId ? { 'X-Manar-Task-Id': taskId } : {},
    );

  beforeAll(async () => {
    const kvPath = `tools/${shortSlug('ms-fixture')}`;
    await humanApp
      .get(OpenBaoKvClient)
      .writeSecret(kvPath, { value: MICROSOFT_FIXTURE_APP.clientSecret });
    tenantClientRef = await tenantDatabaseManager.getClient(tenant.id);
    await ensureMicrosoftFixtureTools(tenantClientRef, {
      fixtureBaseUrl: fixtureBase,
      kvPath,
    });
    // A disabled tool the task is granted: must not appear in the manifest.
    const disabled = await tenantClientRef.tool.create({
      data: {
        name: 'disabled-tool',
        type: 'IAM',
        baseEndpoint: 'http://127.0.0.1:1',
        protocol: 'HTTP',
        credentialReference: { provider: 'ENV', reference: 'NONE' },
        enabled: false,
      },
    });
    await tenantClientRef.toolAction.create({
      data: { toolId: disabled.id, name: 'thing.read', riskBaseScore: 1 },
    });

    const policy = await http()
      .post('/policies')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        name: 'Microsoft Connector Approval Policy',
        description: 'Every Microsoft mutation needs approval.',
        content: microsoftPolicyContent(),
        reason: 'agent runtime e2e',
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

    const a = await enrollAgent('agent-a');
    agentA = a.identity;
    agentAId = a.id;
    agentB = (await enrollAgent('agent-b')).identity;

    task = await createTask({
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
        { toolId: 'disabled-tool', actionId: 'thing.read' },
        { toolId: 'unregistered-tool', actionId: 'x.read' },
      ],
      allowedResourceSelectors: [
        { toolId: MICROSOFT_GRAPH_TOOL, pattern: incidentId },
        { toolId: MICROSOFT_GRAPH_TOOL, pattern: userId },
        { toolId: MICROSOFT_DEFENDER_TOOL, pattern: machineId },
        { toolId: 'disabled-tool', pattern: '*' },
        { toolId: 'unregistered-tool', pattern: '*' },
      ],
      forbiddenActions: [
        {
          toolId: MICROSOFT_GRAPH_TOOL,
          actionId: 'entra.user.sessions.revoke',
        },
      ],
    });
    budgetTask = await createTask({
      allowedToolActions: [],
      allowedResourceSelectors: [],
    });
  }, 120_000);

  describe('tool manifest', () => {
    it('is the effective grant set: minus forbidden, only registered actions of enabled tools', async () => {
      const res = await mtlsRequest(
        agentA,
        'GET',
        `/agent/v1/tasks/${task.id}/tool-manifest`,
      );
      expect(res.status).toBe(200);
      const body = res.body as {
        taskId: string;
        tools: {
          name: string;
          toolId: string;
          actionId: string;
          resourceSelector: string[];
          mutating: boolean;
          destructive: boolean;
          inputSchema: unknown;
          description: string;
        }[];
      };
      expect(body.taskId).toBe(task.id);
      expect(body.tools.map((t) => t.name)).toEqual([
        'microsoft-defender__defender.machine.isolate',
        'microsoft-graph__entra.user.disable',
        'microsoft-graph__entra.user.get',
        'microsoft-graph__security.incident.get',
      ]);
      const isolate = body.tools[0];
      expect(isolate).toMatchObject({
        toolId: MICROSOFT_DEFENDER_TOOL,
        actionId: 'defender.machine.isolate',
        mutating: true,
        destructive: true,
        resourceSelector: [machineId],
        inputSchema: { type: 'object', required: ['comment'] },
      });
      expect(isolate?.description).toMatch(/Isolate a device/);
      expect(body.tools[2]?.resourceSelector).toEqual(
        [incidentId, userId].sort(),
      );
    });

    it('the demo:seed SOC agent task exposes its reads plus disable and isolate', async () => {
      const seeded = await createTask(socAgentTaskGrants());
      const res = await mtlsRequest(
        agentA,
        'GET',
        `/agent/v1/tasks/${seeded.id}/tool-manifest`,
      );
      const tools = (
        res.body as { tools: { name: string; mutating: boolean }[] }
      ).tools;
      expect(tools.map((t) => t.name)).toEqual([
        'microsoft-defender__defender.machine.get',
        'microsoft-defender__defender.machine.isolate',
        'microsoft-graph__entra.user.disable',
        'microsoft-graph__entra.user.get',
        'microsoft-graph__entra.user.risk.get',
        'microsoft-graph__entra.user.signins.list',
        'microsoft-graph__security.alert.get',
        'microsoft-graph__security.incident.get',
      ]);
      expect(tools.filter((t) => t.mutating).map((t) => t.name)).toEqual([
        'microsoft-defender__defender.machine.isolate',
        'microsoft-graph__entra.user.disable',
      ]);
    });

    it('is refused for a task assigned to another agent and for an unknown task', async () => {
      const other = await mtlsRequest(
        agentB,
        'GET',
        `/agent/v1/tasks/${task.id}/tool-manifest`,
      );
      expect(other.status).toBe(403);
      expect(other.body).toMatchObject({
        decision: 'DENY',
        reason: 'not_assigned_agent',
      });
      const unknown = await mtlsRequest(
        agentA,
        'GET',
        `/agent/v1/tasks/${randomUUID()}/tool-manifest`,
      );
      expect(unknown.status).toBe(403);
      expect(unknown.body).toMatchObject({ reason: 'task_not_found' });
    });
  });

  describe('governed MCP server', () => {
    it('initializes and lists the manifest as MCP tools', async () => {
      const init = await mcp(agentA, task.id, 'initialize', {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'e2e', version: '0' },
      });
      expect(init.status).toBe(200);
      expect(init.body).toMatchObject({
        result: { serverInfo: { name: 'manar-governed-mcp' } },
      });

      const list = await mcp(agentA, task.id, 'tools/list');
      expect(list.status).toBe(200);
      const tools = (
        list.body as {
          result: {
            tools: { name: string; inputSchema: Record<string, unknown> }[];
          };
        }
      ).result.tools;
      expect(tools.map((t) => t.name)).toEqual([
        'microsoft-defender__defender.machine.isolate',
        'microsoft-graph__entra.user.disable',
        'microsoft-graph__entra.user.get',
        'microsoft-graph__security.incident.get',
        'manar_approval_status',
      ]);
      expect(tools[0]?.inputSchema).toMatchObject({
        type: 'object',
        properties: {
          resource: { type: 'string' },
          params: { type: 'object', required: ['comment'] },
        },
        required: ['resource'],
      });

      const denied = await mcp(agentB, task.id, 'tools/list');
      expect(denied.body).toMatchObject({
        error: { data: { status: 'DENIED', reason: 'not_assigned_agent' } },
      });
      const get = await mtlsRequest(
        agentA,
        'GET',
        `/agent/v1/tasks/${task.id}/mcp`,
      );
      expect(get.status).toBe(405);
    });

    it('ALLOW: executes a read and returns the tool result with status EXECUTED', async () => {
      const result = await callTool('microsoft-graph__security.incident.get', {
        resource: incidentId,
        params: { expandAlerts: true },
      });
      expect(result.isError).toBe(false);
      expect(result.structuredContent).toMatchObject({
        status: 'EXECUTED',
        outcome: 'SUCCESS',
        success: true,
        data: { id: incidentId, _dataOrigin: 'DEMO_FIXTURE' },
      });

      // ADR-003: the MCP door records its decision, and the execution
      // outcome is linked to it.
      const decision = await tenantClientRef.decision.findFirstOrThrow({
        where: { taskId: task.id, actionId: 'security.incident.get' },
        orderBy: { createdAt: 'desc' },
        include: { toolInvocations: true },
      });
      expect(decision).toMatchObject({
        outcome: 'ALLOW',
        channel: 'MCP',
        stage: 'REQUEST',
        resource: incidentId,
      });
      expect(decision.toolInvocations).toHaveLength(1);
      expect(decision.toolInvocations[0]!.status).toBe('SUCCESS');
    });

    it('DENY: out-of-scope resource and forbidden action come back as isError with the reason', async () => {
      const outOfScope = await callTool('microsoft-graph__entra.user.disable', {
        resource: FIXTURE_SECOND_USER_ID,
      });
      expect(outOfScope).toMatchObject({
        isError: true,
        structuredContent: { status: 'DENIED', reason: 'not_authorized' },
      });
      const forbidden = await callTool(
        'microsoft-graph__entra.user.sessions.revoke',
        {
          resource: userId,
        },
      );
      expect(forbidden).toMatchObject({
        isError: true,
        structuredContent: { status: 'DENIED', reason: 'forbidden_action' },
      });
      const denials = await tenantClientRef.decision.findMany({
        where: { taskId: task.id, outcome: 'DENY', channel: 'MCP' },
      });
      expect(denials.map((d) => d.reasonCodes[0])).toEqual(
        expect.arrayContaining(['not_authorized', 'forbidden_action']),
      );
      expect(
        (await fixtureState()).users.find(
          (u) => u.id === FIXTURE_SECOND_USER_ID,
        )?.accountEnabled,
      ).toBe(true);
    });

    it('PENDING: isolate needs approval; after approval the agent polls and redeems via REST', async () => {
      const before = (await fixtureRequests()).length;
      const args = {
        resource: machineId,
        params: {
          comment: 'Credential dumping on fx-ws-042 (fixture incident 4201)',
        },
      };
      const pending = await callTool(
        'microsoft-defender__defender.machine.isolate',
        args,
      );
      expect(pending.isError).toBe(false);
      expect(pending.structuredContent).toMatchObject({
        status: 'PENDING',
        reason: 'policy_requires_approval',
        riskScore: expect.any(Number) as unknown,
      });
      expect((await fixtureRequests()).length).toBe(before);
      const approvalId = pending.structuredContent.approvalId as string;

      const waiting = await mtlsRequest(
        agentA,
        'GET',
        `/agent/v1/approvals/${approvalId}`,
      );
      expect(waiting.body).toMatchObject({ id: approvalId, status: 'PENDING' });
      expect(waiting.body).not.toHaveProperty('grantToken');

      await http()
        .post(`/approvals/${approvalId}/decide`)
        .set('Authorization', `Bearer ${approverToken}`)
        .send({ decision: 'APPROVE', reason: 'Confirmed compromise (fixture)' })
        .expect(201);
      let grantToken: string | undefined;
      const deadline = Date.now() + 20_000;
      while (!grantToken) {
        const polled = await mtlsRequest(
          agentA,
          'GET',
          `/agent/v1/approvals/${approvalId}`,
        );
        grantToken = (polled.body as { grantToken?: string }).grantToken;
        if (Date.now() > deadline) throw new Error('approval did not resolve');
        if (!grantToken) await new Promise((r) => setTimeout(r, 250));
      }

      const redeemed = await mtlsRequest(
        agentA,
        'POST',
        '/agent/v1/tools/invoke',
        {
          taskId: task.id,
          toolId: MICROSOFT_DEFENDER_TOOL,
          actionId: 'defender.machine.isolate',
          ...args,
          grantToken,
        },
      );
      expect(redeemed.status).toBe(200);
      expect(redeemed.body).toMatchObject({
        success: true,
        data: { type: 'Isolate', machineId },
      });
      expect((await fixtureState()).isolatedMachineIds).toContain(machineId);

      const replay = await mtlsRequest(
        agentA,
        'POST',
        '/agent/v1/tools/invoke',
        {
          taskId: task.id,
          toolId: MICROSOFT_DEFENDER_TOOL,
          actionId: 'defender.machine.isolate',
          ...args,
          grantToken,
        },
      );
      expect(replay.status).toBe(403);
      const replayDecision = await tenantClientRef.decision.findUniqueOrThrow({
        where: { id: (replay.body as { decisionId: string }).decisionId },
      });
      expect(replayDecision).toMatchObject({
        outcome: 'DENY',
        stage: 'GRANT_REDEMPTION',
        channel: 'REST',
        reasonCodes: ['grant_already_consumed'],
      });
    });
  });

  /**
   * ADR-0007: an MCP client finishes an approved action with MCP only. Call,
   * wait with `manar_approval_status`, call the same tool again; the server
   * redeems the single-use grant itself and re-runs the whole decision.
   */
  describe('approved actions over MCP only (ADR-0007)', () => {
    const DISABLE = 'microsoft-graph__entra.user.disable';
    const ISOLATE = 'microsoft-defender__defender.machine.isolate';
    const disableArgs = { resource: userId, params: {} };

    const approve = (approvalId: string) =>
      http()
        .post(`/approvals/${approvalId}/decide`)
        .set('Authorization', `Bearer ${approverToken}`)
        .send({ decision: 'APPROVE', reason: 'MCP e2e (fixture)' })
        .expect(201);

    const status = (
      approvalId: string,
      waitSeconds: number,
      on: { identity?: Identity; taskId?: string } = {},
    ) => callTool('manar_approval_status', { approvalId, waitSeconds }, on);

    async function approvedVia(name: string, args: Record<string, unknown>) {
      const pending = await callTool(name, args);
      expect(pending.structuredContent).toMatchObject({ status: 'PENDING' });
      const approvalId = pending.structuredContent.approvalId as string;
      await approve(approvalId);
      const decided = await status(approvalId, 30);
      expect(decided.structuredContent).toMatchObject({
        approvalId,
        status: 'APPROVED',
      });
      return approvalId;
    }

    it('request -> PENDING -> approve -> same MCP call executes once, recorded as a redemption decision', async () => {
      const pending = await callTool(DISABLE, disableArgs);
      expect(pending.isError).toBe(false);
      expect(pending.structuredContent).toMatchObject({
        status: 'PENDING',
        reason: 'policy_requires_approval',
        nextStep: expect.stringContaining('manar_approval_status') as unknown,
      });
      const approvalId = pending.structuredContent.approvalId as string;

      // Calling again while a person has not decided: same approval, not a second one.
      const again = await callTool(DISABLE, disableArgs);
      expect(again.structuredContent).toMatchObject({
        status: 'PENDING',
        approvalId,
      });
      expect(
        await tenantClientRef.approvalRequest.count({
          where: { taskId: task.id, actionId: 'entra.user.disable' },
        }),
      ).toBe(1);
      const waiting = await status(approvalId, 0);
      expect(waiting.structuredContent).toMatchObject({
        status: 'PENDING',
        tool: DISABLE,
        resource: userId,
      });
      expect(waiting.structuredContent).not.toHaveProperty('grantToken');
      expect(
        (await fixtureState()).users.find((u) => u.id === userId)
          ?.accountEnabled,
      ).toBe(true);

      await approve(approvalId);
      const approved = await status(approvalId, 30);
      expect(approved.structuredContent).toMatchObject({
        status: 'APPROVED',
        nextStep: expect.stringContaining(DISABLE) as unknown,
      });
      expect(approved.structuredContent).not.toHaveProperty('grantToken');

      const done = await callTool(DISABLE, disableArgs);
      expect(done).toMatchObject({
        isError: false,
        structuredContent: { status: 'EXECUTED', outcome: 'SUCCESS' },
      });
      expect(
        (await fixtureState()).users.find((u) => u.id === userId)
          ?.accountEnabled,
      ).toBe(false);

      const grant = await tenantClientRef.authorizationGrant.findUniqueOrThrow({
        where: { approvalRequestId: approvalId },
      });
      expect(grant.consumedAt).not.toBeNull();
      const redemption = await tenantClientRef.decision.findFirstOrThrow({
        where: { grantId: grant.id },
        include: { toolInvocations: true },
      });
      expect(redemption).toMatchObject({
        outcome: 'ALLOW',
        stage: 'GRANT_REDEMPTION',
        channel: 'MCP',
        actionId: 'entra.user.disable',
        resource: userId,
      });
      expect(redemption.toolInvocations[0]?.status).toBe('SUCCESS');

      // Second use: the grant is spent, so the same call asks a person again
      // and nothing runs.
      const before = (await fixtureRequests()).length;
      const second = await callTool(DISABLE, disableArgs);
      expect(second.structuredContent).toMatchObject({ status: 'PENDING' });
      expect(second.structuredContent.approvalId).not.toBe(approvalId);
      expect((await fixtureRequests()).length).toBe(before);
      const used = await status(approvalId, 0);
      expect(used.structuredContent).toMatchObject({
        status: 'APPROVED',
        nextStep: expect.stringContaining('already used') as unknown,
      });
    }, 90_000);

    it('changed parameters after approval: not redeemed, a new approval is asked for, nothing runs', async () => {
      const approvalId = await approvedVia(ISOLATE, {
        resource: machineId,
        params: { comment: 'approved wording' },
      });
      const before = (await fixtureRequests()).length;

      const changed = await callTool(ISOLATE, {
        resource: machineId,
        params: { comment: 'different wording' },
      });

      expect(changed.structuredContent).toMatchObject({ status: 'PENDING' });
      expect(changed.structuredContent.approvalId).not.toBe(approvalId);
      expect((await fixtureRequests()).length).toBe(before);
      const grant = await tenantClientRef.authorizationGrant.findUniqueOrThrow({
        where: { approvalRequestId: approvalId },
      });
      expect(grant.consumedAt).toBeNull();
    }, 90_000);

    it("kill switch after approval refuses the redemption; another task's session cannot use the grant; the grant survives for its own task", async () => {
      const approvalId = await approvedVia(DISABLE, disableArgs);
      const grant = await tenantClientRef.authorizationGrant.findUniqueOrThrow({
        where: { approvalRequestId: approvalId },
      });
      const before = (await fixtureRequests()).length;

      await http()
        .post(`/agents/${agentAId}/kill-switch`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ reason: 'MCP e2e: kill after approval' })
        .expect(201);
      try {
        const killed = await callTool(DISABLE, disableArgs);
        expect(killed).toMatchObject({
          isError: true,
          structuredContent: {
            status: 'DENIED',
            reason: 'agent_kill_switch_active',
          },
        });
        const refusal = await tenantClientRef.decision.findFirstOrThrow({
          where: { grantId: grant.id, outcome: 'DENY' },
        });
        expect(refusal).toMatchObject({
          stage: 'GRANT_REDEMPTION',
          channel: 'MCP',
          reasonCodes: ['agent_kill_switch_active'],
        });
      } finally {
        await http()
          .post(`/agents/${agentAId}/kill-switch/deactivate`)
          .set('Authorization', `Bearer ${ownerToken}`)
          .expect(201);
      }
      expect((await fixtureRequests()).length).toBe(before);

      // G15: a session is bound to its task. Same agent, same tool, same
      // arguments on another task: the first task's grant is not used and its
      // approval is invisible.
      const otherTask = await createTask({
        allowedToolActions: [
          { toolId: MICROSOFT_GRAPH_TOOL, actionId: 'entra.user.disable' },
        ],
        allowedResourceSelectors: [
          { toolId: MICROSOFT_GRAPH_TOOL, pattern: userId },
        ],
      });
      const elsewhere = await callTool(DISABLE, disableArgs, {
        taskId: otherTask.id,
      });
      expect(elsewhere.structuredContent).toMatchObject({ status: 'PENDING' });
      expect(elsewhere.structuredContent.approvalId).not.toBe(approvalId);
      expect(
        await status(approvalId, 0, { taskId: otherTask.id }),
      ).toMatchObject({
        isError: true,
        structuredContent: { status: 'DENIED', reason: 'approval_not_found' },
      });
      // A tool of the first task that the other task was never given.
      expect(
        await callTool(
          ISOLATE,
          { resource: machineId, params: { comment: 'x' } },
          { taskId: otherTask.id },
        ),
      ).toMatchObject({
        isError: true,
        structuredContent: { status: 'DENIED', reason: 'not_authorized' },
      });
      // Another agent on the first task's session: refused, approval invisible.
      expect(
        await callTool(DISABLE, disableArgs, { identity: agentB }),
      ).toMatchObject({
        isError: true,
        structuredContent: { status: 'DENIED' },
      });
      expect(await status(approvalId, 0, { identity: agentB })).toMatchObject({
        isError: true,
        structuredContent: { status: 'DENIED', reason: 'not_assigned_agent' },
      });
      expect((await fixtureRequests()).length).toBe(before);
      expect(
        (
          await tenantClientRef.authorizationGrant.findUniqueOrThrow({
            where: { id: grant.id },
          })
        ).consumedAt,
      ).toBeNull();

      // Kill switch released: the same call on its own task re-decides and runs once.
      const redeemed = await callTool(DISABLE, disableArgs);
      expect(redeemed.structuredContent).toMatchObject({ status: 'EXECUTED' });
      expect(
        await tenantClientRef.decision.count({
          where: { grantId: grant.id, outcome: 'ALLOW' },
        }),
      ).toBe(1);
    }, 120_000);

    it('G16: no MCP method answers without a valid agent identity', async () => {
      const body = JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
      });
      const noCert = await new Promise<
        { status?: number; text: string } | Error
      >((resolve) => {
        const req = https.request(
          {
            host: '127.0.0.1',
            port: agentMtlsPort,
            path: `/agent/v1/tasks/${task.id}/mcp`,
            method: 'POST',
            ca: fullCaChainPem,
            headers: {
              ...MCP_HEADERS,
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(body),
            },
          },
          (res) => {
            let text = '';
            res.on('data', (c: Buffer) => (text += c.toString('utf8')));
            res.on('end', () => resolve({ status: res.statusCode, text }));
          },
        );
        req.on('error', (error) => resolve(error));
        req.end(body);
      });
      if (!(noCert instanceof Error)) {
        expect(noCert.status).toBe(401);
        expect(noCert.text).not.toContain('microsoft');
      }

      const revoked = await enrollAgent('agent-revoked');
      await http()
        .post(`/agents/${revoked.id}/revoke`)
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ reason: 'MCP e2e: G16' })
        .expect(201);
      for (const method of ['initialize', 'tools/list', 'tools/call']) {
        const res = await mcp(revoked.identity, task.id, method, {
          protocolVersion: '2025-06-18',
          capabilities: {},
          clientInfo: { name: 'e2e', version: '0' },
          name: 'manar_approval_status',
          arguments: { approvalId: 'x' },
        });
        expect(res.status).toBe(401);
        expect(JSON.stringify(res.body)).not.toMatch(
          /microsoft|manar_approval_status|manar-governed-mcp/,
        );
      }
    }, 60_000);
  });

  describe('LLM proxy', () => {
    it('forwards to the upstream with the configured model and answers OpenAI-shaped', async () => {
      const res = await chat(
        agentA,
        task.id,
        'Summarise incident 4201 for alice@contoso.example',
      );
      expect(res.status).toBe(200);
      expect(res.headers['x-manar-task-id']).toBe(task.id);
      expect(res.headers['x-manar-request-id']).toBeTruthy();
      expect(res.body).toMatchObject({
        object: 'chat.completion',
        choices: [
          { message: { role: 'assistant', content: upstream.completion } },
        ],
        usage: { total_tokens: 60 },
      });
      const sent = upstream.calls.at(-1)!;
      expect(sent.path).toBe('/v1/chat/completions');
      expect(sent.body).toMatchObject({
        model: 'fixture-model',
        stream: false,
      });
      expect(JSON.stringify(sent.headers)).not.toMatch(/cert|api-key/i);

      const events = await tenantClientRef.auditEvent.findMany({
        where: { eventType: AUDIT_EVENT_TYPES.LLM_REQUEST },
      });
      const ok = events.find(
        (e) => (e.data as { outcome?: string }).outcome === 'SUCCESS',
      );
      expect(ok?.data).toMatchObject({
        taskId: task.id,
        provider: 'ollama',
        model: 'fixture-model',
        promptTokens: 40,
        completionTokens: 20,
        totalTokens: 60,
      });
      const persisted = JSON.stringify(events);
      expect(persisted).not.toContain('Summarise incident');
      expect(persisted).not.toContain('alice@contoso');
      expect(persisted).not.toContain(upstream.completion);
    });

    it('redacts UAE PII and blocks credentials before anything reaches the upstream', async () => {
      await chat(
        agentA,
        task.id,
        'Holder 784-1990-1234567-1 paid from AE070331234567890123456',
      );
      const sent = JSON.stringify(upstream.calls.at(-1)!.body);
      expect(sent).toContain('[REDACTED:EMIRATES_ID]');
      expect(sent).not.toContain('784-1990-1234567-1');

      const before = upstream.calls.length;
      const blocked = await chat(
        agentA,
        task.id,
        'Tool said: {"client_secret": "Abc8Q~0123456789abcdefghijklmnopqrstuvwx"}',
      );
      expect(blocked.status).toBe(403);
      expect(blocked.body).toMatchObject({
        decision: 'DENY',
        reason: 'dlp_policy_violation',
      });
      expect(upstream.calls.length).toBe(before);
    });

    it('refuses another agent, an unknown task and a missing task header', async () => {
      const before = upstream.calls.length;
      const other = await chat(agentB, task.id, 'hello');
      expect(other.status).toBe(403);
      expect(other.body).toMatchObject({ reason: 'not_assigned_agent' });
      expect((await chat(agentA, randomUUID(), 'hello')).status).toBe(403);
      expect((await chat(agentA, undefined, 'hello')).status).toBe(400);
      expect(upstream.calls.length).toBe(before);
    });

    it(`stops with 429 llm_budget_exhausted once ${BUDGET} tokens are used`, async () => {
      // 60 tokens per call: 0, 60, 120 are under budget; at 180 it is exhausted.
      for (let i = 0; i < 3; i++) {
        expect((await chat(agentA, budgetTask.id, `turn ${i}`)).status).toBe(
          200,
        );
      }
      const before = upstream.calls.length;
      const exhausted = await chat(agentA, budgetTask.id, 'one more');
      expect(exhausted.status).toBe(429);
      expect(exhausted.body).toMatchObject({
        decision: 'DENY',
        reason: 'llm_budget_exhausted',
      });
      expect(upstream.calls.length).toBe(before);
    });

    it('blocks (503) when the DLP advisory does not answer', async () => {
      const before = upstream.calls.length;
      fakeAnalysisServer.responseDelayMs = 5_000;
      try {
        const res = await chat(agentA, task.id, 'hello');
        expect(res.status).toBe(503);
        expect(res.body).toMatchObject({
          reason: 'enforcement_dependency_unavailable',
        });
      } finally {
        fakeAnalysisServer.responseDelayMs = 0;
      }
      expect(upstream.calls.length).toBe(before);
    }, 30_000);
  });
});
