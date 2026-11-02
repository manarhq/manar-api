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
import { AiAdvisoryClient } from '../src/ai-advisory/ai-advisory-client.service';
import type { AppConfig } from '../src/config/env.validation';
import {
  codingTaskGrants,
  ensureGitLabTool,
  gitlabPolicyContent,
} from '../src/cli/commands/gitlab-connector-register.command';
import {
  buildGitLabFixtureApp,
  GITLAB_FIXTURE_DEFAULTS,
} from '../packages/demo-soc-tools/src/gitlab/fixture';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';
import { FakeAnalysisServiceServer } from './support/fake-analysis-service-server';

/**
 * ADR-0012: a coding agent drives the GitLab catalog over the governed MCP
 * server (mTLS -> tools/call -> authorize -> policy -> approval workflow ->
 * same tools/call again (ADR-0007) -> credential broker -> OpenBao ->
 * GitLabToolAdapter) against the in-process GitLab DEMO FIXTURE, with the
 * coding pack's default policy. State is re-checked on the fixture, not
 * trusted from the gateway's answer. Says nothing about a live GitLab; the
 * live smoke run is in docs/reports.
 */
describe('GitLab connector through the governed MCP server (DEMO FIXTURE e2e)', () => {
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

  const USER_PASSWORD = 'Passw0rd!Test';
  const TOOL = 'gitlab-demo';
  const P = GITLAB_FIXTURE_DEFAULTS.project;

  const shortSlug = (label: string) =>
    `gitlab-${label}-${randomUUID().slice(0, 8)}`;

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
      AI_ADVISORY_DLP_TIMEOUT_MS: 2000,
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
                Accept: 'application/json, text/event-stream',
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
    const res = await fetch(`${fixtureBase}/gitlab/_fixture/state`);
    return (await res.json()) as {
      branches: Record<string, { sha: string; files: Record<string, string> }>;
      protectedBranches: string[];
      mergeRequests: { iid: number; state: string }[];
    };
  }

  async function fixtureWrites() {
    const res = await fetch(`${fixtureBase}/gitlab/_fixture/requests`);
    return (
      (await res.json()) as { requests: { method: string; path: string }[] }
    ).requests.filter((r) => r.method !== 'GET');
  }

  beforeAll(async () => {
    fakeAnalysisServer = new FakeAnalysisServiceServer();
    const analysisTarget = await fakeAnalysisServer.start();

    fixture = buildGitLabFixtureApp();
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
        name: 'GitLab connector e2e',
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
    if (tenant) await cleanupTenant(tenant);
    await control?.$disconnect();
  }, 60_000);

  it('reads, branch, commit and MR run at once; a direct commit to main and another project are refused; a merge runs only after a person approves and the agent repeats the call', async () => {
    const http = () => request(humanApp.getHttpServer());

    // ---- Setup: tool + fixture token in OpenBao + pack policy + task ----
    const kvPath = `tools/${shortSlug('gl-fixture')}`;
    await humanApp
      .get(OpenBaoKvClient)
      .writeSecret(kvPath, { value: GITLAB_FIXTURE_DEFAULTS.token });
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    await ensureGitLabTool(tenantClient, {
      name: TOOL,
      baseEndpoint: `${fixtureBase}/gitlab/api/v4`,
      project: P,
      kvPath,
      dataOrigin: 'DEMO_FIXTURE',
    });

    const policy = await http()
      .post('/policies')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        name: 'Coding agents pack: GitLab',
        description:
          'Reads and feature-branch work allowed; risky changes need a person.',
        content: gitlabPolicyContent(TOOL, P),
        reason: 'gitlab connector e2e',
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

    const agentId = (
      (
        await http()
          .post('/agents')
          .set('Authorization', `Bearer ${ownerToken}`)
          .send({ slug: shortSlug('agent'), displayName: 'Coding agent e2e' })
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
          name: `GitLab e2e ${randomUUID().slice(0, 8)}`,
          assignedAgentId: agentId,
          ...codingTaskGrants(TOOL),
          expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
          riskCeiling: 50,
          maxExecutions: 20,
        })
        .expect(201)
    ).body as { id: string };

    let rpcId = 0;
    async function call(actionId: string, args: Record<string, unknown>) {
      rpcId += 1;
      const res = await mtlsRequest(
        identity,
        'POST',
        `/agent/v1/tasks/${task.id}/mcp`,
        {
          jsonrpc: '2.0',
          id: rpcId,
          method: 'tools/call',
          params: {
            name: actionId.startsWith('manar_')
              ? actionId
              : `${TOOL}__${actionId}`,
            arguments: args,
          },
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

    // ---- tools/list: the whole catalog, nothing else of this tool ----
    rpcId += 1;
    const list = await mtlsRequest(
      identity,
      'POST',
      `/agent/v1/tasks/${task.id}/mcp`,
      {
        jsonrpc: '2.0',
        id: rpcId,
        method: 'tools/list',
      },
    );
    const names = (
      list.body as { result: { tools: { name: string }[] } }
    ).result.tools.map((t) => t.name);
    expect(names.filter((n) => n.startsWith(`${TOOL}__`))).toHaveLength(13);

    // ---- 1. Reads, branch, commit, MR: ALLOW, executed at once ----
    const tree = await call('gitlab.repo.tree.list', { resource: P });
    expect(tree.structuredContent).toMatchObject({
      status: 'EXECUTED',
      success: true,
    });
    expect(
      (
        await call('gitlab.branch.create', {
          resource: `${P}:feature/hello`,
          params: { ref: 'main' },
        })
      ).structuredContent,
    ).toMatchObject({ status: 'EXECUTED', success: true });
    const commitArgs = {
      message: 'docs: say hello',
      actions: [
        { action: 'create', file_path: 'HELLO.md', content: 'hello\n' },
      ],
    };
    expect(
      (
        await call('gitlab.commit.create', {
          resource: `${P}:feature/hello`,
          params: commitArgs,
        })
      ).structuredContent,
    ).toMatchObject({ status: 'EXECUTED', success: true });
    const mr = await call('gitlab.mr.create', {
      resource: P,
      params: {
        sourceBranch: 'feature/hello',
        targetBranch: 'main',
        title: 'docs: say hello',
      },
    });
    expect(mr.structuredContent).toMatchObject({
      status: 'EXECUTED',
      data: { iid: 1, state: 'opened' },
    });

    // ---- 2. A direct commit to protected main, another project: DENY, nothing sent ----
    const writesBefore = (await fixtureWrites()).length;
    const direct = await call('gitlab.commit.create', {
      resource: `${P}:main`,
      params: commitArgs,
    });
    expect(direct).toMatchObject({
      isError: true,
      structuredContent: { status: 'DENIED', reason: 'policy_denied' },
    });
    const elsewhere = await call('gitlab.branch.create', {
      resource: 'manar/manar-api:x',
      params: { ref: 'main' },
    });
    expect(elsewhere).toMatchObject({
      isError: true,
      structuredContent: { status: 'DENIED', reason: 'policy_denied' },
    });
    expect((await fixtureWrites()).length).toBe(writesBefore);
    expect(
      (await fixtureState()).branches.main!.files['HELLO.md'],
    ).toBeUndefined();

    // ---- 3. Merge: PENDING, a person approves, the same call runs it once ----
    const reviewed = await call('gitlab.mr.get', { resource: `${P}!1` });
    const mergeArgs = {
      resource: `${P}!1`,
      params: {
        sha: (reviewed.structuredContent.data as { sha: string }).sha,
        targetBranch: 'main',
      },
    };
    const pending = await call('gitlab.mr.merge', mergeArgs);
    expect(pending.structuredContent).toMatchObject({
      status: 'PENDING',
      reason: 'policy_requires_approval',
    });
    const approvalId = pending.structuredContent.approvalId as string;
    expect((await fixtureWrites()).length).toBe(writesBefore);

    await http()
      .post(`/approvals/${approvalId}/decide`)
      .set('Authorization', `Bearer ${approverToken}`)
      .send({ decision: 'APPROVE', reason: 'Reviewed the change (fixture)' })
      .expect(201);
    const waited = await call('manar_approval_status', {
      approvalId,
      waitSeconds: 30,
    });
    expect(waited.structuredContent).toMatchObject({ status: 'APPROVED' });

    const merged = await call('gitlab.mr.merge', mergeArgs);
    expect(merged.structuredContent).toMatchObject({
      status: 'EXECUTED',
      data: { state: 'merged' },
    });
    expect((await fixtureState()).branches.main!.files['HELLO.md']).toBe(
      'hello\n',
    );
    const redemption = await tenantClient.decision.findFirstOrThrow({
      where: {
        taskId: task.id,
        actionId: 'gitlab.mr.merge',
        stage: 'GRANT_REDEMPTION',
      },
    });
    expect(redemption).toMatchObject({
      outcome: 'ALLOW',
      channel: 'MCP',
      resource: `${P}!1`,
    });

    // ---- 4. High-risk changes: PENDING at a high risk score ----
    const variable = await call('gitlab.project.variable.set', {
      resource: P,
      params: { key: 'DEPLOY_ENV', value: 'staging' },
    });
    expect(variable.structuredContent).toMatchObject({ status: 'PENDING' });
    const protection = await call('gitlab.branch.protection.change', {
      resource: `${P}:main`,
      params: { protect: false },
    });
    expect(protection.structuredContent).toMatchObject({ status: 'PENDING' });
    const highRisk = await tenantClient.approvalRequest.findMany({
      where: {
        taskId: task.id,
        actionId: {
          in: [
            'gitlab.project.variable.set',
            'gitlab.branch.protection.change',
          ],
        },
      },
    });
    expect(highRisk).toHaveLength(2);
    for (const a of highRisk) expect(a.riskScore).toBeGreaterThanOrEqual(85);
    expect((await fixtureState()).protectedBranches).toEqual(['main']);

    // ---- Records: no token anywhere ----
    const invocations = await tenantClient.toolInvocation.findMany({
      where: { taskId: task.id },
    });
    expect(invocations.map((i) => i.status).every((s) => s === 'SUCCESS')).toBe(
      true,
    );
    expect(invocations).toHaveLength(6);
    const persisted = JSON.stringify([
      invocations,
      await tenantClient.auditEvent.findMany(),
      await tenantClient.decision.findMany({ where: { taskId: task.id } }),
    ]);
    expect(persisted).not.toContain(GITLAB_FIXTURE_DEFAULTS.token);
  }, 120_000);
});
