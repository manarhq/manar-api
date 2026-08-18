import 'dotenv/config';
import * as https from 'node:https';
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
 * Integration pass (Phase 7a + Phase 7b, "out of scope this phase" note in
 * both design specs -- see docs/tool-gateway.md's "Any real connection to
 * Phase 7a's actual demo tool service" line): the first end-to-end proof
 * that the *real*, running `packages/demo-soc-tools` service (not either
 * phase's own synthetic fixtures -- `test/tool-gateway.e2e-spec.ts` uses a
 * local `HttpFixtureServer`/`McpTestServer` stand-in, and
 * `packages/demo-soc-tools`'s own suite never involves manar-api at all)
 * actually gets driven end-to-end through the whole pipeline: real task
 * grant -> real OpenFGA authorization check -> real PolicyEngine/RiskEngine
 * -> real CredentialBrokerService/OpenBaoSecretProvider -> real
 * `HttpToolAdapter` HTTP call -> the real demo-soc-tools container's
 * in-memory state actually changes, independently re-verified by calling
 * that service directly (not by trusting `POST /agent/v1/tools/invoke`'s
 * own response).
 *
 * Requires `packages/demo-soc-tools` reachable at `DEMO_SOC_TOOLS_BASE_URL`
 * (default `http://localhost:3101`, matching `deploy/docker-compose.yml`'s
 * host port mapping -- `pnpm infra:up` brings this up automatically) and
 * its `DEMO_TOOLS_API_KEY` (default `manar-dev-demo-tools-key`, matching
 * that same compose file's dev default) so this suite can independently
 * re-verify state by calling the service directly, the same way
 * `CredentialBrokerService` calls it via `HttpToolAdapter`.
 *
 * `HttpToolAdapter` (`src/tools/http-tool.adapter.ts`) has one fixed wire
 * convention -- `POST {baseEndpoint}/{action.name}` with a JSON body
 * `{ resource, params }` -- which does not match demo-soc-tools' own
 * hand-rolled REST-ish `/hosts/:id[/action]` routes (those predate this
 * integration pass and exist for that package's own direct tests). Rather
 * than special-case the generic, already-tested adapter for one demo tool,
 * `packages/demo-soc-tools/src/routes/edr.ts` gained two small
 * action-name wrapper routes (`POST /v1/edr/get-host`,
 * `POST /v1/edr/isolate-host`) that call the exact same `DemoStore`
 * methods as the existing REST routes -- see that file's own doc comment.
 */
describe('Tool Gateway <-> real demo-soc-tools (integration e2e)', () => {
  const DEMO_TOOLS_BASE_URL =
    process.env.DEMO_SOC_TOOLS_BASE_URL ?? 'http://localhost:3101';
  const DEMO_TOOLS_API_KEY =
    process.env.DEMO_TOOLS_API_KEY ?? 'manar-dev-demo-tools-key';
  const DEMO_HOST_ID = 'WS-042'; // seeded by packages/demo-soc-tools/src/state/seed-data.ts

  let humanApp: NestFastifyApplication;
  let agentMtlsApp: NestFastifyApplication;
  let humanEndpoint: string;
  let agentMtlsPort: number;
  let fullCaChainPem: string;

  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let adminToken: string;

  const ADMIN_USERNAME = `toolgwdemo-admin-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `toolgwdemo-${label}-${randomUUID().slice(0, 8)}`;
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

  /** Calls the real, running demo-soc-tools service's unauthenticated dev-reset endpoint -- restores deterministic seed state (WS-042 not isolated) regardless of what an earlier run/test left behind. */
  async function resetDemoTools(): Promise<void> {
    const res = await fetch(`${DEMO_TOOLS_BASE_URL}/_demo/reset`, {
      method: 'POST',
    });
    if (!res.ok) {
      throw new Error(
        `Failed to reset demo-soc-tools state at ${DEMO_TOOLS_BASE_URL} (HTTP ${res.status}) -- is 'pnpm infra:up' running?`,
      );
    }
  }

  /** Calls the real demo-soc-tools service directly (never through manar-api's own gateway) to independently re-verify its actual state. */
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

  /** Creates a root Task via the real human HTTP API -- Phase 4/5's real enrollment/task flow, not a shortcut. */
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
        name: `Demo integration task ${randomUUID().slice(0, 8)}`,
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

  /** Writes a `Tool` row directly against the real tenant database -- no human-facing registration API exists this phase (see test/tool-gateway.e2e-spec.ts's identical precedent). */
  async function registerTool(input: {
    name: string;
    baseEndpoint: string;
    credentialReference: { provider: 'OPENBAO'; reference: string };
  }): Promise<{ id: string; name: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.tool.create({
      data: {
        name: input.name,
        type: 'EDR',
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
    riskBaseScore: number;
    mutating: boolean;
    destructive: boolean;
  }): Promise<{ id: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.toolAction.create({
      data: {
        toolId: input.toolId,
        name: input.name,
        riskBaseScore: input.riskBaseScore,
        inputSchema: { type: 'object' },
        mutating: input.mutating,
        destructive: input.destructive,
      },
    });
  }

  interface InvokeResponse {
    status: number;
    body: unknown;
  }

  /** Raw mTLS POST /agent/v1/tools/invoke -- no SDK method exists for this endpoint yet, same as test/tool-gateway.e2e-spec.ts's identical helper. */
  function invokeToolOverMtls(
    identity: Pick<
      AgentIdentity,
      'certificatePem' | 'caChainPem' | 'privateKeyPem'
    >,
    body: unknown,
  ): Promise<InvokeResponse> {
    const bodyText = JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port: agentMtlsPort,
          path: '/agent/v1/tools/invoke',
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

  beforeAll(async () => {
    await resetDemoTools();

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

    tenant = await provisioning.provisionTenant({
      slug: uniqueSlug('tenant'),
      name: 'Tool Gateway Demo Integration Test Tenant',
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
    await resetDemoTools();
  }, 60_000);

  it('authorize -> policy -> risk -> credential broker -> real demo-soc-tools EDR isolate-host actually isolates the real WS-042 host', async () => {
    // 1. Store the real demo-soc-tools bearer credential in the real
    // OpenBao KV v2 engine -- exactly the way test/tool-gateway.e2e-spec.ts
    // scenario 3 proves OPENBAO-backed credentials resolve, just with a
    // real value the real demo-soc-tools container actually accepts,
    // instead of a synthetic random one no real tool ever checks.
    const kvMountPath = process.env.OPENBAO_KV_MOUNT_PATH ?? 'secret';
    const kvPath = `tools/${uniqueSlug('demo-soc-tools-edr')}`;
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

    // 2. Register a real Tool row pointing at the real, running
    // demo-soc-tools container's /v1/edr path, plus the two ToolAction
    // rows this scenario exercises -- matching HttpToolAdapter's
    // `POST {baseEndpoint}/{action.name}` wire convention (see this file's
    // own doc comment for the demo-soc-tools-side adjustment that made
    // this line up).
    const tool = await registerTool({
      name: uniqueSlug('demo-edr'),
      baseEndpoint: `${DEMO_TOOLS_BASE_URL}/v1/edr/`,
      credentialReference: { provider: 'OPENBAO', reference: kvPath },
    });
    await registerToolAction({
      toolId: tool.id,
      name: 'get-host',
      riskBaseScore: 5,
      mutating: false,
      destructive: false,
    });
    const isolateAction = await registerToolAction({
      toolId: tool.id,
      name: 'isolate-host',
      riskBaseScore: 15,
      mutating: true,
      destructive: false,
    });

    // 3. Real enrollment + a real Task grant scoped to exactly
    // `edr.isolate-host` (and `edr.get-host`, to prove the read path too)
    // on `WS-042` -- Phase 4/5's real API, not a shortcut. riskCeiling is
    // raised above this scenario's deterministic score (baseline 10 +
    // riskBaseScore 15 + mutating 15 = 40) so the real pipeline reaches
    // ALLOW, not REQUIRE_APPROVAL -- this test is about proving the real
    // tool call happens, not re-testing Phase 6's approval routing (see
    // test/tool-gateway.e2e-spec.ts scenario 6 for that).
    const agent = await createEnrolledAgent('demo-edr');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [
        { toolId: tool.name, actionId: 'get-host' },
        { toolId: tool.name, actionId: 'isolate-host' },
      ],
      allowedResourceSelectors: [{ toolId: tool.name, pattern: DEMO_HOST_ID }],
      riskCeiling: 50,
    });

    // 4. Sanity check via the gateway itself: WS-042 starts not isolated.
    const getResponse = await invokeToolOverMtls(agent.identity, {
      taskId: task.id,
      toolId: tool.name,
      actionId: 'get-host',
      resource: DEMO_HOST_ID,
      params: {},
    });
    expect(getResponse.status).toBe(200);
    const getBody = getResponse.body as {
      success: boolean;
      data: { id: string; isolated: boolean };
    };
    expect(getBody.success).toBe(true);
    expect(getBody.data.id).toBe(DEMO_HOST_ID);
    expect(getBody.data.isolated).toBe(false);

    // 5. The real action under test: POST /agent/v1/tools/invoke for
    // edr.isolate-host on WS-042, through the whole real pipeline.
    const isolateResponse = await invokeToolOverMtls(agent.identity, {
      taskId: task.id,
      toolId: tool.name,
      actionId: 'isolate-host',
      resource: DEMO_HOST_ID,
      params: {},
    });
    expect(isolateResponse.status).toBe(200);
    const isolateBody = isolateResponse.body as {
      success: boolean;
      data: { id: string; isolated: boolean };
    };
    expect(isolateBody.success).toBe(true);
    expect(isolateBody.data.isolated).toBe(true);

    // 6. The proof this integration pass exists for: independently
    // re-verify against the real demo-soc-tools service directly (never
    // trusting the gateway's own response) that WS-042 is now actually
    // isolated.
    const realHost = await getRealDemoHost(DEMO_HOST_ID);
    expect(realHost.isolated).toBe(true);

    // 7. A SUCCESS ToolInvocation row was recorded for the real call.
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const invocationRow = await tenantClient.toolInvocation.findFirstOrThrow({
      where: {
        taskId: task.id,
        resource: DEMO_HOST_ID,
        actionId: isolateAction.id,
      },
      orderBy: { createdAt: 'desc' },
    });
    expect(invocationRow.status).toBe('SUCCESS');
  }, 30_000);
});
