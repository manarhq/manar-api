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
import { TemporalClientService } from '../src/temporal/temporal-client.service';
import { ApprovalWorkflow } from '../src/temporal/workflows/approval.workflow';
import { ApprovalRequestService } from '../src/approvals/approval-request.service';
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

/**
 * Phase 8 (Approval Engine) — every mandatory scenario from the design
 * spec's "Testing" section
 * (docs/superpowers/specs/2026-08-19-phase8-approvals-design.md), run
 * against real Postgres/Keycloak/OpenBao/OpenFGA/Temporal (`pnpm infra:up`)
 * and the real SDK. See docs/approvals.md.
 *
 * A real Temporal `Worker` is bootstrapped in-process (`beforeAll`,
 * against the real local Temporal server `TEMPORAL_ADDRESS` names) using
 * the exact same `WorkerAppModule`/`ApprovalActivitiesFactory`
 * `src/worker.main.ts` uses for the real separate worker process — the
 * Temporal SDK doesn't care whether the process polling a task queue is
 * literally a separate OS process or an in-process `Worker` instance; this
 * is the same "boot the real thing in-process for test convenience"
 * posture `test/tool-gateway-demo-integration.e2e-spec.ts` already uses
 * for both Nest HTTP apps.
 */
describe('Approval Engine (e2e)', () => {
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

  /** approvalRequestId -> promise the worker's finalize Activity awaits first (test 9). */
  const heldFinalizations = new Map<string, Promise<void>>();

  const DEMO_TOOLS_BASE_URL =
    process.env.DEMO_SOC_TOOLS_BASE_URL ?? 'http://localhost:3101';
  const DEMO_TOOLS_API_KEY =
    process.env.DEMO_TOOLS_API_KEY ?? 'manar-dev-demo-tools-key';
  // Seeded by packages/demo-soc-tools/src/state/seed-data.ts.
  // Deliberately NOT WS-042 -- see releaseRealDemoHost's doc comment.
  const DEMO_HOST_ID = 'WS-017';

  const ADMIN_USERNAME = `approvals-admin-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `approvals-${label}-${randomUUID().slice(0, 8)}`;
  }

  /**
   * A deliberately short slug for the tenant and for agents specifically.
   * `Agent.identifier` (`agent://<tenantSlug>/<agentSlug>`, see
   * `src/agents/agent-identifier.ts`) is embedded verbatim as a CSR's URI
   * Subject Alternative Name and signed by the real local OpenBao PKI
   * engine (Phase 4, entirely untouched by Phase 8) — empirically, that
   * signing step rejects the *whole* identifier string once it exceeds 63
   * characters (`idna: invalid label ...`), the classic RFC 1035 DNS-label
   * limit, which OpenBao's URI-SAN validation applies to this non-DNS
   * scheme's string as a whole. `uniqueSlug`'s own longer, more readable
   * prefix (used for tools/policies/tenants elsewhere, which never feed a
   * cert SAN) would blow that budget for several of this suite's agent
   * labels, so agents and the tenant itself use this shorter form instead.
   */
  function shortSlug(label: string): string {
    return `apv-${label}-${randomUUID().slice(0, 8)}`;
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

  /**
   * Releases exactly one host on the real demo-soc-tools service — used
   * instead of that service's global `POST /_demo/reset` (which
   * `test/tool-gateway-demo-integration.e2e-spec.ts` already uses,
   * resetting *every* seeded host including `WS-042`). Vitest runs e2e
   * spec files concurrently by default; a global reset from this file
   * racing against that other file's own in-flight isolate/verify
   * sequence on `WS-042` would flakily un-isolate it out from under that
   * test. This suite instead targets the *other* seeded host (`WS-017` —
   * see `packages/demo-soc-tools/src/state/seed-data.ts`) and only ever
   * touches that one host's state, via its own per-host release endpoint.
   */
  async function releaseRealDemoHost(hostId: string): Promise<void> {
    const res = await fetch(
      `${DEMO_TOOLS_BASE_URL}/v1/edr/hosts/${hostId}/release`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${DEMO_TOOLS_API_KEY}` },
      },
    );
    if (!res.ok) {
      throw new Error(
        `Failed to release demo-soc-tools host "${hostId}" at ${DEMO_TOOLS_BASE_URL} (HTTP ${res.status}) -- is 'pnpm infra:up' running?`,
      );
    }
  }

  async function getRealDemoHost(
    hostId: string,
  ): Promise<{ id: string; isolated: boolean }> {
    const res = await fetch(`${DEMO_TOOLS_BASE_URL}/v1/edr/hosts/${hostId}`, {
      headers: { Authorization: `Bearer ${DEMO_TOOLS_API_KEY}` },
    });
    if (!res.ok) {
      throw new Error(
        `GET /v1/edr/hosts/${hostId} against the real demo-soc-tools service failed (HTTP ${res.status})`,
      );
    }
    return (await res.json()) as { id: string; isolated: boolean };
  }

  /** Creates a PENDING_ENROLLMENT agent + enrollment token via the real human HTTP API, then enrolls it via the real SDK against the real mTLS listener -- same pattern as test/tool-gateway.e2e-spec.ts. */
  async function createEnrolledAgent(slugLabel: string): Promise<{
    agentId: string;
    slug: string;
    identity: AgentIdentity;
  }> {
    const slug = shortSlug(slugLabel);
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

    return { agentId, slug, identity };
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
    maxExecutions?: number;
  }): Promise<{ id: string; status: string; expiresAt: string }> {
    const response = await request(humanApp.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        name: `Approvals test task ${randomUUID().slice(0, 8)}`,
        assignedAgentId: input.assignedAgentId,
        allowedToolActions: input.allowedToolActions,
        allowedResourceSelectors: input.allowedResourceSelectors,
        forbiddenActions: [],
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        riskCeiling: input.riskCeiling,
        maxExecutions: input.maxExecutions,
      })
      .expect(201);
    return response.body as { id: string; status: string; expiresAt: string };
  }

  async function registerTool(input: {
    name: string;
    baseEndpoint: string;
    protocol?: 'HTTP' | 'MCP';
    credentialReference?: {
      provider: 'ENV' | 'OPENBAO';
      reference: string;
    };
  }): Promise<{ id: string; name: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.tool.create({
      data: {
        name: input.name,
        type: 'TEST',
        baseEndpoint: input.baseEndpoint,
        protocol: input.protocol ?? 'HTTP',
        credentialReference: input.credentialReference ?? {
          provider: 'ENV',
          reference: 'PATH',
        },
        enabled: true,
      },
    });
  }

  async function registerToolAction(input: {
    toolId: string;
    name: string;
    riskBaseScore?: number;
    mutating?: boolean;
    destructive?: boolean;
  }): Promise<{ id: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.toolAction.create({
      data: {
        toolId: input.toolId,
        name: input.name,
        riskBaseScore: input.riskBaseScore ?? 90,
        inputSchema: { type: 'object' },
        mutating: input.mutating ?? false,
        destructive: input.destructive ?? false,
      },
    });
  }

  interface PolicyRuleInput {
    toolId: string;
    actionId: string;
    resourcePattern?: string;
    effect: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
  }

  async function createPolicy(
    name: string,
    rules: PolicyRuleInput[],
  ): Promise<{ id: string; latestVersion: { id: string } }> {
    const response = await request(humanApp.getHttpServer() as App)
      .post('/policies')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name, content: { rules } })
      .expect(201);
    return response.body as { id: string; latestVersion: { id: string } };
  }

  async function createPolicyVersion(
    policyId: string,
    rules: PolicyRuleInput[],
  ): Promise<{ id: string }> {
    const response = await request(humanApp.getHttpServer() as App)
      .post(`/policies/${policyId}/versions`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ content: { rules } })
      .expect(201);
    return response.body as { id: string };
  }

  async function publishVersion(
    policyId: string,
    versionId: string,
  ): Promise<void> {
    await request(humanApp.getHttpServer() as App)
      .post(`/policies/${policyId}/versions/${versionId}/publish`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(201);
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
          timeout: 15_000,
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
    reason?: string,
  ): Promise<RawResponse> {
    const res = await request(humanApp.getHttpServer() as App)
      .post(`/approvals/${approvalId}/decide`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ decision, reason });
    return { status: res.status, body: res.body as unknown };
  }

  interface ApprovalPollBody {
    id: string;
    status: string;
    grantToken?: string;
    grantExpiresAt?: string;
  }

  /** Polls GET /agent/v1/approvals/:id until `status` leaves PENDING (or the timeout elapses) -- eventual consistency between signaling the workflow and its Activity actually writing the new status/grant. */
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

  /**
   * Directly creates an `ApprovalRequest` row and starts its
   * `ApprovalWorkflow` with a caller-chosen `ttlMs` — real Temporal, real
   * worker, real database, real `GrantService` Activities, exactly what
   * `ToolInvokeController.startApproval` does, just using the *exact same*
   * real `ApprovalRequestService`/`TemporalClientService` provider
   * instances pulled directly from the running `agentMtlsApp` (no second,
   * hand-rolled implementation). This exists only because
   * `APPROVAL_REQUEST_TTL_MS` (`src/approvals/approvals.config.ts`) is
   * resolved once, process-wide, at `ConfigModule.forRoot()`'s own
   * import-time side effect — there is no per-request or per-test way to
   * override it short of restarting the whole process with a different
   * environment, so the "approval request itself expires" e2e scenario
   * (below) drives the exact same real workflow directly with a short
   * `ttlMs` instead. Every *other* scenario in this suite goes through
   * `POST /agent/v1/tools/invoke` for creation, exercising the real HTTP
   * trigger path — this helper exists for exactly one scenario.
   */
  async function startShortLivedApprovalRequest(input: {
    taskId: string;
    agentId: string;
    toolId: string;
    actionId: string;
    resource: string;
    ttlMs: number;
  }): Promise<string> {
    const approvalRequestService = agentMtlsApp.get(ApprovalRequestService);
    const temporalClient = agentMtlsApp.get(TemporalClientService);
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);

    const expiresAt = new Date(Date.now() + input.ttlMs);
    const temporalWorkflowId = `approval-test-${randomUUID()}`;

    const approvalRequest = await approvalRequestService.create(tenantClient, {
      taskId: input.taskId,
      agentId: input.agentId,
      toolId: input.toolId,
      actionId: input.actionId,
      resource: input.resource,
      params: {},
      riskScore: 5,
      // Release 2026-11-11 (brief §3.4): the persisted risk breakdown.
      // This helper builds a low-risk fixture request, so the whole score
      // is deterministic and no advisory signal was involved.
      deterministicRiskScore: 5,
      aiAdvisoryScore: null,
      advisoryUnavailable: true,
      riskReasonCodes: ['baseline'],
      taskRiskCeiling: 50,
      requiredReason: 'policy_requires_approval',
      policyVersionId: null,
      expiresAt,
      temporalWorkflowId,
    });

    await temporalClient.workflow.start(ApprovalWorkflow, {
      workflowId: temporalWorkflowId,
      taskQueue: temporalClient.taskQueue,
      args: [
        {
          tenantId: tenant.id,
          approvalRequestId: approvalRequest.id,
          expiresAtEpochMs: expiresAt.getTime(),
        },
      ],
    });

    return approvalRequest.id;
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

    // The real Temporal worker (see class doc comment) -- the exact same
    // WorkerAppModule/ApprovalActivitiesFactory src/worker.main.ts uses,
    // polling the exact same real local Temporal server/task queue
    // ToolInvokeController/ApprovalsController talk to via
    // TemporalClientService.
    workerModuleFixture = await Test.createTestingModule({
      imports: [WorkerAppModule],
    }).compile();
    const realActivities = workerModuleFixture
      .get(ApprovalActivitiesFactory)
      .build();
    // Test 9 holds the real finalize Activity for its one request until both
    // concurrent decide calls have signaled; every other request is untouched.
    const activities: typeof realActivities = {
      ...realActivities,
      finalizeApprovalDecision: async (input) => {
        await heldFinalizations.get(input.approvalRequestId);
        return realActivities.finalizeApprovalDecision(input);
      },
    };
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
      name: 'Approval Engine Test Tenant',
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
    // SECURITY_ADMIN covers /tasks, /policies, AND /approvals/:id/decide
    // (one of the three roles that endpoint accepts) in a single test user.
    await assignRealmRole(tenant.keycloakRealm, adminUserId, 'SECURITY_ADMIN');

    adminToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username: ADMIN_USERNAME,
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
    await releaseRealDemoHost(DEMO_HOST_ID);
  }, 60_000);

  it('1. full flow: invoke -> PENDING_APPROVAL -> decide APPROVE -> poll -> grant -> retry invoke with grant -> real demo-soc-tools host is actually isolated', async () => {
    // Deterministic starting state for this suite's one dedicated host
    // (WS-017) -- see releaseRealDemoHost's doc comment for why this is a
    // per-host release rather than the global /_demo/reset.
    await releaseRealDemoHost(DEMO_HOST_ID);

    const kvMountPath = process.env.OPENBAO_KV_MOUNT_PATH ?? 'secret';
    const kvPath = `tools/${uniqueSlug('demo-edr')}`;
    const openBaoAddr = process.env.OPENBAO_ADDR ?? 'http://localhost:8200';
    const openBaoToken = process.env.OPENBAO_TOKEN ?? 'manar-dev-root-token';
    const writeResponse = await fetch(
      `${openBaoAddr}/v1/${kvMountPath}/data/${kvPath}`,
      {
        method: 'POST',
        headers: {
          'X-Vault-Token': openBaoToken,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: { value: DEMO_TOOLS_API_KEY } }),
      },
    );
    expect(writeResponse.ok).toBe(true);

    const tool = await registerTool({
      name: uniqueSlug('demo-edr'),
      baseEndpoint: `${DEMO_TOOLS_BASE_URL}/v1/edr/`,
      credentialReference: { provider: 'OPENBAO', reference: kvPath },
    });
    await registerToolAction({
      toolId: tool.id,
      name: 'isolate-host',
      // baseline 10 + riskBaseScore 15 + mutating 15 = 40 -- above the
      // riskCeiling below, so this reaches APPROVAL_REQUIRED (same
      // deterministic mechanism test/tool-gateway-demo-integration.e2e-spec.ts
      // uses for the ALLOW case, just with a lower riskCeiling here).
      riskBaseScore: 15,
      mutating: true,
    });

    const agent = await createEnrolledAgent('full-flow');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: tool.name, actionId: 'isolate-host' }],
      allowedResourceSelectors: [{ toolId: tool.name, pattern: DEMO_HOST_ID }],
      riskCeiling: 30,
    });

    const initialInvoke = await invokeToolOverMtls(agent.identity, {
      taskId: task.id,
      toolId: tool.name,
      actionId: 'isolate-host',
      resource: DEMO_HOST_ID,
      params: {},
    });
    expect(initialInvoke.status).toBe(202);
    const initialBody = initialInvoke.body as {
      status: string;
      reason: string;
      riskScore: number;
      approvalId: string;
    };
    expect(initialBody.status).toBe('PENDING');
    expect(initialBody.reason).toBe('risk_ceiling_exceeded');
    expect(initialBody.approvalId).toBeTruthy();

    // Real host is not isolated yet -- no tool call was ever attempted.
    const beforeApprove = await getRealDemoHost(DEMO_HOST_ID);
    expect(beforeApprove.isolated).toBe(false);

    const decideResponse = await decideApproval(
      initialBody.approvalId,
      'APPROVE',
      'looks legitimate',
    );
    expect(decideResponse.status).toBe(201);

    const polled = await waitForApprovalStatus(
      agent.identity,
      initialBody.approvalId,
    );
    expect(polled.status).toBe('APPROVED');
    expect(polled.grantToken).toBeTruthy();

    const retryInvoke = await invokeToolOverMtls(agent.identity, {
      taskId: task.id,
      toolId: tool.name,
      actionId: 'isolate-host',
      resource: DEMO_HOST_ID,
      params: {},
      grantToken: polled.grantToken,
    });
    expect(retryInvoke.status).toBe(200);
    const retryBody = retryInvoke.body as {
      success: boolean;
      data: { isolated: boolean };
    };
    expect(retryBody.success).toBe(true);
    expect(retryBody.data.isolated).toBe(true);

    // Independently re-verify against the real demo-soc-tools service
    // directly -- never trusting the gateway's own response alone.
    const afterApprove = await getRealDemoHost(DEMO_HOST_ID);
    expect(afterApprove.isolated).toBe(true);

    // ADR-003: both attempts left a durable Decision, the execution is
    // linked to the redemption decision, and the redemption decision hashed
    // exactly the inputs the grant was bound to.
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const decisions = await tenantClient.decision.findMany({
      where: { taskId: task.id },
      orderBy: { createdAt: 'asc' },
    });
    expect(decisions.map((d) => [d.outcome, d.stage, d.channel])).toEqual([
      ['APPROVAL_REQUIRED', 'REQUEST', 'REST'],
      ['ALLOW', 'GRANT_REDEMPTION', 'REST'],
    ]);
    const grant = await tenantClient.authorizationGrant.findFirstOrThrow({
      where: { taskId: task.id },
    });
    expect(decisions[1]!.grantId).toBe(grant.id);
    expect(decisions[1]!.inputsHash).toBe(grant.parameterHash);
    expect(decisions[0]!.inputsHash).toBe(grant.parameterHash);
    expect(grant.consumedAt).not.toBeNull();
    const invocation = await tenantClient.toolInvocation.findFirstOrThrow({
      where: { taskId: task.id },
    });
    expect(invocation).toMatchObject({
      decisionId: decisions[1]!.id,
      status: 'SUCCESS',
    });
    const started = await tenantClient.auditEvent.findFirstOrThrow({
      where: {
        eventType: 'tool.invocation.started',
        data: { path: ['taskId'], equals: task.id },
      },
    });
    expect(started.data).toMatchObject({ decisionId: decisions[1]!.id });
  }, 60_000);

  it('2. decide DENY -> ApprovalRequest.status DENIED, retry without a grant never executes', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('deny-tool'),
        baseEndpoint,
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('deny-flow');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      const initialInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-deny',
        params: {},
      });
      expect(initialInvoke.status).toBe(202);
      const { approvalId } = initialInvoke.body as { approvalId: string };

      const decideResponse = await decideApproval(
        approvalId,
        'DENY',
        'not authorized for this host',
      );
      expect(decideResponse.status).toBe(201);

      const polled = await waitForApprovalStatus(agent.identity, approvalId);
      expect(polled.status).toBe('DENIED');
      expect(polled.grantToken).toBeUndefined();

      // Retrying the exact same request (no grantToken) goes through
      // AuthorizationService.authorize fresh -- still APPROVAL_REQUIRED
      // (nothing about the task/policy/risk changed), never ALLOW, and
      // certainly never a tool call.
      const retryInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-deny',
        params: {},
      });
      expect(retryInvoke.status).toBe(202);
      expect(fixture.requests).toHaveLength(0);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('3. approval replay: reusing an already-consumed grant is denied, no second tool call', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('replay-tool'),
        baseEndpoint,
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('replay');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      const initialInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-replay',
        params: { q: 1 },
      });
      const { approvalId } = initialInvoke.body as { approvalId: string };
      await decideApproval(approvalId, 'APPROVE');
      const polled = await waitForApprovalStatus(agent.identity, approvalId);
      expect(polled.status).toBe('APPROVED');
      const grantToken = polled.grantToken!;

      const body = {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-replay',
        params: { q: 1 },
        grantToken,
      };

      const firstUse = await invokeToolOverMtls(agent.identity, body);
      expect(firstUse.status).toBe(200);
      expect(fixture.requests).toHaveLength(1);

      // Section 80: the exact same grant, used again -- denied, and the
      // tool is never called a second time.
      const secondUse = await invokeToolOverMtls(agent.identity, body);
      expect(secondUse.status).toBe(403);
      const secondBody = secondUse.body as { decision: string; reason: string };
      expect(secondBody.decision).toBe('DENY');
      expect(secondBody.reason).toBe('grant_already_consumed');
      expect(fixture.requests).toHaveLength(1);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('4. parameter binding: a grant issued for one resource is rejected when retried against a different resource', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('param-bind-tool'),
        baseEndpoint,
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('param-binding');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      const initialInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-original',
        params: { q: 'original' },
      });
      const { approvalId } = initialInvoke.body as { approvalId: string };
      await decideApproval(approvalId, 'APPROVE');
      const polled = await waitForApprovalStatus(agent.identity, approvalId);
      expect(polled.status).toBe('APPROVED');
      const grantToken = polled.grantToken!;

      // Same grant token, but a *different* resource than what it was
      // issued for -- Section 80's mandatory parameter-binding invariant.
      const mismatchedResource = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-different',
        params: { q: 'original' },
        grantToken,
      });
      expect(mismatchedResource.status).toBe(403);
      expect((mismatchedResource.body as { reason: string }).reason).toBe(
        'grant_mismatch',
      );

      // Same grant token, same resource, but different params -- also
      // rejected (the hash covers params too, not just resource).
      const mismatchedParams = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-original',
        params: { q: 'tampered' },
        grantToken,
      });
      expect(mismatchedParams.status).toBe(403);
      expect((mismatchedParams.body as { reason: string }).reason).toBe(
        'grant_mismatch',
      );

      expect(fixture.requests).toHaveLength(0);

      // The original, unmodified request still works -- proves the grant
      // itself was never actually invalidated by the mismatched attempts
      // above, only those specific mismatched requests were rejected.
      const correctUse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-original',
        params: { q: 'original' },
        grantToken,
      });
      expect(correctUse.status).toBe(200);
      expect(fixture.requests).toHaveLength(1);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('5. a grant used after its own expiry is denied', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('expiry-tool'),
        baseEndpoint,
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('grant-expiry');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      const initialInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-expiry',
        params: {},
      });
      const { approvalId } = initialInvoke.body as { approvalId: string };
      await decideApproval(approvalId, 'APPROVE');
      const polled = await waitForApprovalStatus(agent.identity, approvalId);
      expect(polled.status).toBe('APPROVED');
      const grantToken = polled.grantToken!;

      // Directly force the persisted AuthorizationGrant row's expiresAt
      // into the past -- deterministic and instant, rather than actually
      // waiting out APPROVAL_GRANT_TTL_MS (5 minutes by default); same
      // "write a row directly, no API exists to produce this state on
      // demand" precedent test/policy-risk.e2e-spec.ts's simulated
      // policy-load-failure scenario and test/tool-gateway.e2e-spec.ts's
      // direct Tool/ToolAction writes already establish.
      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      const grantRow = await tenantClient.authorizationGrant.findFirstOrThrow({
        where: { approvalRequestId: approvalId },
      });
      await tenantClient.authorizationGrant.update({
        where: { id: grantRow.id },
        data: { expiresAt: new Date(Date.now() - 1_000) },
      });

      const expiredUse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-expiry',
        params: {},
        grantToken,
      });
      expect(expiredUse.status).toBe(403);
      expect((expiredUse.body as { reason: string }).reason).toBe(
        'grant_expired',
      );
      expect(fixture.requests).toHaveLength(0);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('6. nobody decides in time -> the workflow completes EXPIRED, no grant is ever issuable', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('expire-request-tool'),
        baseEndpoint,
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('request-expiry');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      // See startShortLivedApprovalRequest's own doc comment for why this
      // scenario drives ApprovalWorkflow directly with a short ttlMs
      // rather than going through POST /agent/v1/tools/invoke (which would
      // use the real, process-wide APPROVAL_REQUEST_TTL_MS -- 30 minutes
      // by default, far too long for a real-time e2e test; the
      // time-skipping unit test, src/temporal/workflows/approval.workflow.spec.ts,
      // is the authoritative coverage for the timeout mechanism itself).
      const approvalId = await startShortLivedApprovalRequest({
        taskId: task.id,
        agentId: agent.agentId,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-request-expiry',
        ttlMs: 3_000,
      });

      // Nobody ever calls decideApproval for this request -- wait past
      // its own short ttlMs above.
      const polled = await waitForApprovalStatus(
        agent.identity,
        approvalId,
        15_000,
      );
      expect(polled.status).toBe('EXPIRED');
      expect(polled.grantToken).toBeUndefined();

      // Deciding after the workflow already completed its own timeout
      // finds ApprovalRequest.status no longer PENDING -> rejected.
      const lateDecision = await decideApproval(approvalId, 'APPROVE');
      expect(lateDecision.status).toBe(409);

      expect(fixture.requests).toHaveLength(0);
    } finally {
      await fixture.stop();
    }
  }, 40_000);

  it('7. policy republished stricter (DENY) between the request and the decision -> re-evaluation catches it, no grant issued even though a human approved', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('midflight-tool'),
        baseEndpoint,
      });
      await registerToolAction({
        toolId: tool.id,
        name: 'sensitive-action',
        riskBaseScore: 5,
      });

      const { id: policyId, latestVersion } = await createPolicy(
        uniqueSlug('midflight-policy'),
        [
          {
            toolId: tool.name,
            actionId: 'sensitive-action',
            effect: 'APPROVAL_REQUIRED',
          },
        ],
      );
      await publishVersion(policyId, latestVersion.id);

      const agent = await createEnrolledAgent('midflight');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [
          { toolId: tool.name, actionId: 'sensitive-action' },
        ],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 100, // generous -- APPROVAL_REQUIRED here comes from the policy rule, not the risk ceiling
      });

      const initialInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'sensitive-action',
        resource: 'host-midflight',
        params: {},
      });
      expect(initialInvoke.status).toBe(202);
      const initialBody = initialInvoke.body as {
        reason: string;
        approvalId: string;
      };
      expect(initialBody.reason).toBe('policy_requires_approval');

      // Republish a *stricter* version for the exact same tool/action
      // while the request is still pending -- nobody has decided yet.
      const stricterVersion = await createPolicyVersion(policyId, [
        {
          toolId: tool.name,
          actionId: 'sensitive-action',
          effect: 'DENY',
        },
      ]);
      await publishVersion(policyId, stricterVersion.id);

      // A human approves anyway (unaware the policy just changed
      // underneath them) -- re-evaluation at approval time must still
      // catch it.
      const decideResponse = await decideApproval(
        initialBody.approvalId,
        'APPROVE',
        'approved before noticing the policy changed',
      );
      expect(decideResponse.status).toBe(201);

      const polled = await waitForApprovalStatus(
        agent.identity,
        initialBody.approvalId,
      );
      expect(polled.status).toBe('DENIED');
      expect(polled.grantToken).toBeUndefined();

      // Retrying without a grant is still blocked -- the now-published
      // DENY policy rule denies it outright on the next
      // AuthorizationService.authorize call.
      const retryInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'sensitive-action',
        resource: 'host-midflight',
        params: {},
      });
      expect(retryInvoke.status).toBe(403);
      expect((retryInvoke.body as { reason: string }).reason).toBe(
        'policy_denied',
      );

      expect(fixture.requests).toHaveLength(0);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('7b. S6/F7: policy republished to DENY after the grant was issued -> redemption re-runs the decision and refuses; DENY recorded; grant left unconsumed; nothing executes', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('redeem-tool'),
        baseEndpoint,
      });
      await registerToolAction({
        toolId: tool.id,
        name: 'sensitive-action',
        riskBaseScore: 5,
      });
      const { id: policyId, latestVersion } = await createPolicy(
        uniqueSlug('redeem-policy'),
        [
          {
            toolId: tool.name,
            actionId: 'sensitive-action',
            effect: 'APPROVAL_REQUIRED',
          },
        ],
      );
      await publishVersion(policyId, latestVersion.id);

      const agent = await createEnrolledAgent('redeem-revalidate');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [
          { toolId: tool.name, actionId: 'sensitive-action' },
        ],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 100,
      });
      const body = {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'sensitive-action',
        resource: 'host-redeem',
        params: { reason: 'containment' },
      };

      const initialInvoke = await invokeToolOverMtls(agent.identity, body);
      expect(initialInvoke.status).toBe(202);
      const { approvalId } = initialInvoke.body as { approvalId: string };
      expect((await decideApproval(approvalId, 'APPROVE', 'ok')).status).toBe(
        201,
      );
      const polled = await waitForApprovalStatus(agent.identity, approvalId);
      expect(polled.status).toBe('APPROVED');
      expect(polled.grantToken).toBeTruthy();

      // The grant exists and is unexpired. Now the policy changes.
      const stricterVersion = await createPolicyVersion(policyId, [
        { toolId: tool.name, actionId: 'sensitive-action', effect: 'DENY' },
      ]);
      await publishVersion(policyId, stricterVersion.id);

      const redeem = await invokeToolOverMtls(agent.identity, {
        ...body,
        grantToken: polled.grantToken,
      });
      expect(redeem.status).toBe(403);
      const denied = redeem.body as { reason: string; decisionId: string };
      expect(denied.reason).toBe('policy_denied');
      expect(fixture.requests).toHaveLength(0);

      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      const decision = await tenantClient.decision.findUniqueOrThrow({
        where: { id: denied.decisionId },
      });
      const grant = await tenantClient.authorizationGrant.findFirstOrThrow({
        where: { taskId: task.id },
      });
      expect(decision).toMatchObject({
        outcome: 'DENY',
        stage: 'GRANT_REDEMPTION',
        reasonCodes: ['policy_denied'],
        policyVersionId: stricterVersion.id,
        grantId: grant.id,
      });
      expect(grant.consumedAt).toBeNull();
      const rejected = await tenantClient.auditEvent.findFirstOrThrow({
        where: {
          eventType: 'approval.grant_rejected',
          data: { path: ['decisionId'], equals: denied.decisionId },
        },
      });
      expect(rejected.data).toMatchObject({ reason: 'policy_denied' });
      expect(
        await tenantClient.toolInvocation.count({ where: { taskId: task.id } }),
      ).toBe(0);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('7c. ADR-003 G14: when the decision record cannot be written the request is a 503 and the tool is never contacted', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    try {
      const tool = await registerTool({
        name: uniqueSlug('g14-tool'),
        baseEndpoint,
      });
      await registerToolAction({
        toolId: tool.id,
        name: 'read-thing',
        riskBaseScore: 0,
      });
      const agent = await createEnrolledAgent('g14');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'read-thing' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 100,
      });
      const body = {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'read-thing',
        resource: 'thing-1',
        params: {},
      };

      // Control: with the decision store available, this request executes.
      expect((await invokeToolOverMtls(agent.identity, body)).status).toBe(200);
      expect(fixture.requests).toHaveLength(1);

      await tenantClient.$executeRawUnsafe(
        'ALTER TABLE "decisions" RENAME TO "decisions_g14"',
      );
      const failed = await invokeToolOverMtls(agent.identity, body);
      expect(failed.status).toBe(503);
      expect((failed.body as { reason: string }).reason).toBe(
        'enforcement_dependency_unavailable',
      );
      expect(fixture.requests).toHaveLength(1);
      // The failed transaction also rolled back its execution-count increment.
      const taskRow = await tenantClient.task.findUniqueOrThrow({
        where: { id: task.id },
      });
      expect(taskRow.executionCount).toBe(1);
    } finally {
      await tenantClient
        .$executeRawUnsafe('ALTER TABLE "decisions_g14" RENAME TO "decisions"')
        .catch(() => undefined);
      await fixture.stop();
    }
  }, 30_000);

  it('8. GET /agent/v1/approvals/:id never leaks a grant to an agent it was not assigned to', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('cross-agent-tool'),
        baseEndpoint,
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const owner = await createEnrolledAgent('cross-agent-owner');
      const outsider = await createEnrolledAgent('cross-agent-outsider');
      const task = await createTask({
        assignedAgentId: owner.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      const initialInvoke = await invokeToolOverMtls(owner.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-cross-agent',
        params: {},
      });
      const { approvalId } = initialInvoke.body as { approvalId: string };
      await decideApproval(approvalId, 'APPROVE');
      await waitForApprovalStatus(owner.identity, approvalId);

      // A different, unrelated agent (never assigned this task at all)
      // polls the exact same approvalId -- 404, never a grant, never even
      // a confirmation the request exists.
      const outsiderPoll = await pollApprovalOverMtls(
        outsider.identity,
        approvalId,
      );
      expect(outsiderPoll.status).toBe(404);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('9. concurrent decide race (Phase 14 security cleanup 1): two genuinely concurrent decide calls on the same request both report the one decision that actually won, never a discarded one', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('race-tool'),
        baseEndpoint,
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('race');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      const initialInvoke = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-race',
        params: {},
      });
      const { approvalId } = initialInvoke.body as { approvalId: string };

      // Reproduces Phase 11b Part 2's exact finding: two genuinely
      // concurrent decide calls for the same ApprovalRequest -- a
      // double-click, or two different approvers -- both pass the
      // `status === 'PENDING'` precheck and both successfully signal the
      // workflow. Before this phase's fix, both would return 201 with
      // `decision` simply echoing whatever each caller submitted -- even
      // though ApprovalWorkflow's decide handler is first-signal-wins, so
      // at most one of "APPROVE" and "DENY" was ever actually recorded.
      // Firing them via Promise.all is reliable here specifically because
      // the fix under test makes this handler await the *entire*
      // finalizeApprovalDecision Activity (real DB writes, a fresh
      // policy/risk re-evaluation) before responding -- signal delivery
      // itself is near-instant, so there is a wide, real window in which
      // both signals land before the workflow ever closes.
      //
      // That window is not wide on a slow CI runner: pipeline 894 saw the
      // second call reach the handler after the first had already returned,
      // so it was a plain late call (409, like `third` below) rather than a
      // race. The finalize Activity for this request is therefore held until
      // Temporal has recorded both signals, i.e. until both calls have passed
      // the PENDING check and are awaiting the result. The race is then real
      // on every run, and the assertions below are unchanged.
      let releaseFinalize!: () => void;
      heldFinalizations.set(
        approvalId,
        new Promise<void>((resolve) => (releaseFinalize = resolve)),
      );
      const tenantClientForRace = await tenantDatabaseManager.getClient(
        tenant.id,
      );
      const { temporalWorkflowId } =
        await tenantClientForRace.approvalRequest.findUniqueOrThrow({
          where: { id: approvalId },
        });
      const workflowHandle = agentMtlsApp
        .get(TemporalClientService)
        .workflow.getHandle(temporalWorkflowId);
      const decided = Promise.all([
        decideApproval(approvalId, 'APPROVE', 'first caller'),
        decideApproval(approvalId, 'DENY', 'second caller'),
      ]);
      try {
        const deadline = Date.now() + 10_000;
        for (;;) {
          const { events } = await workflowHandle.fetchHistory();
          const signals = (events ?? []).filter(
            (e) => e.workflowExecutionSignaledEventAttributes,
          ).length;
          if (signals >= 2 || Date.now() > deadline) break;
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
      } finally {
        releaseFinalize();
        heldFinalizations.delete(approvalId);
      }
      const [first, second] = await decided;

      expect(first.status).toBe(201);
      expect(second.status).toBe(201);

      const firstBody = first.body as { status: string; decision?: string };
      const secondBody = second.body as {
        status: string;
        decision?: string;
      };

      // Both responses must agree on the one decision that actually took
      // effect -- neither is allowed to report its own submitted decision
      // if that decision lost the race.
      expect(['APPROVED', 'DENIED']).toContain(firstBody.status);
      expect(secondBody.status).toBe(firstBody.status);
      expect(secondBody.decision).toBe(firstBody.decision);

      // Only one ApprovalDecision row was ever recorded -- Temporal's
      // signal handler is first-signal-wins, never both.
      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      const decisions = await tenantClient.approvalDecision.findMany({
        where: { approvalRequestId: approvalId },
      });
      expect(decisions).toHaveLength(1);
      expect(decisions[0]!.decision).toBe(firstBody.decision);

      const polled = await waitForApprovalStatus(agent.identity, approvalId);
      expect(polled.status).toBe(firstBody.status);
      if (firstBody.status === 'APPROVED') {
        expect(polled.grantToken).toBeTruthy();
      } else {
        expect(polled.grantToken).toBeFalsy();
      }

      // A third decide call, now that the request is genuinely no longer
      // PENDING, is correctly rejected -- the fix is about response
      // accuracy for a true race, not about accepting decisions forever.
      const third = await decideApproval(approvalId, 'APPROVE', 'too late');
      expect(third.status).toBe(409);
    } finally {
      await fixture.stop();
    }
  }, 30_000);
});
