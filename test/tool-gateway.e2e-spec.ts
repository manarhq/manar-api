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
import { HttpFixtureServer } from './support/http-fixture-server';
import { McpTestServer } from './support/mcp-test-server';

/**
 * Mandatory Phase 7b (Tool Registry, Credential Broker & Proxy Execution)
 * scenarios — design spec's "Testing" section — run against a real HTTP
 * server, real local Postgres, real local Keycloak, real local OpenBao
 * (both its PKI engine, for agent identity, and its KV v2 engine, for
 * `OpenBaoSecretProvider`), and real local OpenFGA (`pnpm infra:up`),
 * plus this phase's own lightweight local HTTP fixture server and minimal
 * MCP test server (see test/support/) standing in for Phase 7a's real
 * tool backends, which this workstream does not depend on.
 *
 * There is no human-facing API to register a `Tool`/`ToolAction` (out of
 * scope this phase, same as Phase 6's "no API can ever produce malformed
 * PolicyVersion content" precedent in test/policy-risk.e2e-spec.ts) — this
 * suite writes those rows directly against the real tenant database via
 * `TenantDatabaseManager`, exactly like that precedent.
 */
describe('Tool Gateway (e2e)', () => {
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

  const ADMIN_USERNAME = `toolgw-admin-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `toolgw-${label}-${randomUUID().slice(0, 8)}`;
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

  /** Writes a `Tool` row directly against the real tenant database — no human-facing registration API exists this phase (out of scope, see class doc comment). */
  async function registerTool(input: {
    name: string;
    protocol: 'HTTP' | 'MCP';
    baseEndpoint: string;
    credentialReference: { provider: 'ENV' | 'OPENBAO'; reference: string };
    enabled?: boolean;
  }): Promise<{ id: string; name: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.tool.create({
      data: {
        name: input.name,
        type: 'TEST',
        baseEndpoint: input.baseEndpoint,
        protocol: input.protocol,
        credentialReference: input.credentialReference,
        enabled: input.enabled ?? true,
      },
    });
  }

  async function registerToolAction(input: {
    toolId: string;
    name: string;
    riskBaseScore?: number;
    inputSchema?: unknown;
    mutating?: boolean;
    destructive?: boolean;
  }): Promise<{ id: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    return tenantClient.toolAction.create({
      data: {
        toolId: input.toolId,
        name: input.name,
        riskBaseScore: input.riskBaseScore ?? 10,
        inputSchema: input.inputSchema as never,
        mutating: input.mutating ?? false,
        destructive: input.destructive ?? false,
      },
    });
  }

  interface InvokeResponse {
    status: number;
    body: unknown;
  }

  /** Performs a raw mTLS POST /agent/v1/tools/invoke -- no SDK method exists for this endpoint yet (Phase 7b added no SDK surface, mirroring how test/agent-identity.e2e-spec.ts's whoamiOverMtls talks to /agent/v1/whoami directly). */
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
      name: 'Tool Gateway Test Tenant',
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

  it('1. HTTP tool: full authorize -> invoke round trip against a real local HTTP fixture server returns the tool real response', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const credentialValue = `env-cred-${randomUUID()}`;
      process.env.TOOLGW_TEST_HTTP_CRED = credentialValue;

      const tool = await registerTool({
        name: uniqueSlug('http-tool'),
        protocol: 'HTTP',
        baseEndpoint,
        credentialReference: {
          provider: 'ENV',
          reference: 'TOOLGW_TEST_HTTP_CRED',
        },
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('http-round-trip');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
      });

      // toolId/actionId here are exactly the same opaque strings Phase
      // 5/6's grant model already used (Tool.name / ToolAction.name --
      // see ToolRegistryService's own doc comment for why this needed no
      // schema change to Task grants, AuthorizeRequest, or the OpenFGA
      // model).
      const invokeResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-1',
        params: { q: 'anything' },
      });

      expect(invokeResponse.status).toBe(200);
      const body = invokeResponse.body as { success: boolean; data: unknown };
      expect(body.success).toBe(true);
      expect(body.data).toEqual({
        echoed: { resource: 'host-1', params: { q: 'anything' } },
      });

      expect(fixture.requests).toHaveLength(1);
      expect(fixture.requests[0]!.headers.authorization).toBe(
        `Bearer ${credentialValue}`,
      );

      delete process.env.TOOLGW_TEST_HTTP_CRED;
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('2. MCP tool: the same round trip via McpToolAdapter against the minimal test MCP server -- proves MCP goes through the identical pipeline', async () => {
    const mcpServer = new McpTestServer();
    const baseEndpoint = await mcpServer.start();
    try {
      const credentialValue = `env-cred-${randomUUID()}`;
      process.env.TOOLGW_TEST_MCP_CRED = credentialValue;

      const tool = await registerTool({
        name: uniqueSlug('mcp-tool'),
        protocol: 'MCP',
        baseEndpoint,
        credentialReference: {
          provider: 'ENV',
          reference: 'TOOLGW_TEST_MCP_CRED',
        },
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('mcp-round-trip');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
      });

      const invokeResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-2',
        params: { query: 'anything' },
      });

      expect(invokeResponse.status).toBe(200);
      const body = invokeResponse.body as { success: boolean; data: unknown };
      expect(body.success).toBe(true);
      expect(body.data).toEqual({ found: true, resource: 'host-2' });

      expect(mcpServer.calls).toHaveLength(1);
      expect(mcpServer.calls[0]!.authorizationHeader).toBe(
        `Bearer ${credentialValue}`,
      );

      delete process.env.TOOLGW_TEST_MCP_CRED;
    } finally {
      await mcpServer.stop();
    }
  }, 30_000);

  it('3. OPENBAO-backed credential: CredentialBrokerService resolves through OpenBaoSecretProvider transparently', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const kvMountPath = process.env.OPENBAO_KV_MOUNT_PATH ?? 'secret';
      const kvPath = `tools/${uniqueSlug('openbao-tool')}`;
      const credentialValue = `openbao-cred-${randomUUID()}`;

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
          body: JSON.stringify({ data: { value: credentialValue } }),
        },
      );
      expect(writeResponse.ok).toBe(true);

      const tool = await registerTool({
        name: uniqueSlug('openbao-http-tool'),
        protocol: 'HTTP',
        baseEndpoint,
        credentialReference: { provider: 'OPENBAO', reference: kvPath },
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('openbao-cred');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
      });

      const invokeResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-3',
        params: {},
      });

      expect(invokeResponse.status).toBe(200);
      expect((invokeResponse.body as { success: boolean }).success).toBe(true);
      expect(fixture.requests).toHaveLength(1);
      expect(fixture.requests[0]!.headers.authorization).toBe(
        `Bearer ${credentialValue}`,
      );
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('4. the credential never appears in the HTTP response, in any captured log line, or in the stored ToolInvocation row', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    let originalStdoutWrite: typeof process.stdout.write | undefined;
    const capturedStdout: string[] = [];
    try {
      const credentialValue = `super-secret-leak-check-${randomUUID()}`;
      process.env.TOOLGW_TEST_LEAK_CRED = credentialValue;

      const tool = await registerTool({
        name: uniqueSlug('leak-check-tool'),
        protocol: 'HTTP',
        baseEndpoint,
        credentialReference: {
          provider: 'ENV',
          reference: 'TOOLGW_TEST_LEAK_CRED',
        },
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('leak-check');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
      });

      originalStdoutWrite = process.stdout.write.bind(process.stdout);
      process.stdout.write = (
        chunk: string | Uint8Array,
        ...rest: unknown[]
      ): boolean => {
        capturedStdout.push(typeof chunk === 'string' ? chunk : String(chunk));
        return (
          originalStdoutWrite as (
            chunk: string | Uint8Array,
            ...rest: unknown[]
          ) => boolean
        )(chunk, ...rest);
      };

      const invokeResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-4',
        params: { q: 'x' },
      });

      process.stdout.write = originalStdoutWrite;

      expect(invokeResponse.status).toBe(200);
      const rawResponseText = JSON.stringify(invokeResponse.body);
      expect(rawResponseText).not.toContain(credentialValue);

      const allStdout = capturedStdout.join('');
      expect(allStdout).not.toContain(credentialValue);

      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      const invocationRow = await tenantClient.toolInvocation.findFirstOrThrow({
        where: { taskId: task.id, resource: 'host-4' },
        orderBy: { createdAt: 'desc' },
      });
      expect(JSON.stringify(invocationRow)).not.toContain(credentialValue);
      expect(invocationRow.status).toBe('SUCCESS');

      delete process.env.TOOLGW_TEST_LEAK_CRED;
    } finally {
      if (originalStdoutWrite) process.stdout.write = originalStdoutWrite;
      await fixture.stop();
    }
  }, 30_000);

  it('5. DENY from AuthorizationService -> no HTTP/MCP call is made at all', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('deny-tool'),
        protocol: 'HTTP',
        baseEndpoint,
        credentialReference: { provider: 'ENV', reference: 'PATH' }, // never resolved -- DENY happens first
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('deny-no-call');
      // A task with no grant at all for this tool/action -> OpenFGA DENY.
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'other_action' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
      });

      const invokeResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-5',
        params: {},
      });

      expect(invokeResponse.status).toBe(403);
      expect((invokeResponse.body as { decision: string }).decision).toBe(
        'DENY',
      );
      expect(fixture.requests).toHaveLength(0);

      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      const invocationCount = await tenantClient.toolInvocation.count({
        where: { taskId: task.id },
      });
      expect(invocationCount).toBe(0);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('6. APPROVAL_REQUIRED -> no call made, response clearly signals pending (not success or failure)', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('approval-tool'),
        protocol: 'HTTP',
        baseEndpoint,
        credentialReference: { provider: 'ENV', reference: 'PATH' },
      });
      await registerToolAction({
        toolId: tool.id,
        name: 'lookup',
        // A high riskBaseScore pushes the deterministic risk score above
        // this task's own (default) riskCeiling, producing APPROVAL_REQUIRED
        // via the existing, unchanged Phase 6 pipeline -- exactly the same
        // mechanism test/policy-risk.e2e-spec.ts's scenario 3 exercises,
        // just fed by a real registered ToolAction now instead of the
        // deleted keyword heuristic.
        riskBaseScore: 90,
      });

      const agent = await createEnrolledAgent('approval-no-call');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        riskCeiling: 5,
      });

      const invokeResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-6',
        params: {},
      });

      expect(invokeResponse.status).toBe(202);
      const body = invokeResponse.body as {
        status: string;
        reason: string;
        riskScore: number;
      };
      expect(body.status).toBe('PENDING');
      expect(body.reason).toBe('risk_ceiling_exceeded');
      expect(body.riskScore).toBeGreaterThan(5);

      expect(fixture.requests).toHaveLength(0);

      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      const invocationCount = await tenantClient.toolInvocation.count({
        where: { taskId: task.id },
      });
      expect(invocationCount).toBe(0);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('7. a disabled tool fails invocation cleanly even though authorization ALLOWs', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      const tool = await registerTool({
        name: uniqueSlug('disabled-tool'),
        protocol: 'HTTP',
        baseEndpoint,
        credentialReference: { provider: 'ENV', reference: 'PATH' },
        enabled: false,
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      const agent = await createEnrolledAgent('disabled-tool');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
      });

      const invokeResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-7',
        params: {},
      });

      expect(invokeResponse.status).toBe(409);
      expect(fixture.requests).toHaveLength(0);

      // A FAILURE ToolInvocation row IS created (both tool/action ids are
      // known by the time the disabled check runs) -- see
      // CredentialBrokerService's own doc comment.
      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      const invocationRow = await tenantClient.toolInvocation.findFirstOrThrow({
        where: { taskId: task.id, resource: 'host-7' },
      });
      expect(invocationRow.status).toBe('FAILURE');
      expect(invocationRow.errorMessage).toMatch(/disabled/i);
    } finally {
      await fixture.stop();
    }
  }, 30_000);

  it('8. ToolInvocation rows are created for both success and failure, never containing raw request/response payloads', async () => {
    const fixture = new HttpFixtureServer();
    const baseEndpoint = await fixture.start();
    try {
      // First call succeeds (default fixture echo), second is made to fail
      // via a fixed 500 response.
      const tool = await registerTool({
        name: uniqueSlug('success-failure-tool'),
        protocol: 'HTTP',
        baseEndpoint,
        credentialReference: { provider: 'ENV', reference: 'PATH' },
      });
      await registerToolAction({ toolId: tool.id, name: 'lookup' });

      // Short label: the full agent identifier (agent://<tenantSlug>/<slug>)
      // becomes this workload identity's certificate CN, which OpenBao's
      // idna-based validation caps at 63 octets (a pre-existing Phase 4
      // constraint, confirmed empirically -- unrelated to this phase).
      const agent = await createEnrolledAgent('success-fail');
      const task = await createTask({
        assignedAgentId: agent.agentId,
        allowedToolActions: [{ toolId: tool.name, actionId: 'lookup' }],
        allowedResourceSelectors: [{ toolId: tool.name, pattern: '*' }],
        maxExecutions: 10,
      });

      const successResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-8-success',
        params: { secretish: 'raw-request-payload-marker' },
      });
      expect(successResponse.status).toBe(200);
      expect((successResponse.body as { success: boolean }).success).toBe(true);

      fixture.setResponse({ status: 503, body: { error: 'unavailable' } });
      const failureResponse = await invokeToolOverMtls(agent.identity, {
        taskId: task.id,
        toolId: tool.name,
        actionId: 'lookup',
        resource: 'host-8-failure',
        params: { secretish: 'raw-response-payload-marker' },
      });
      expect(failureResponse.status).toBe(200); // the gateway itself succeeded -- the tool call it made did not
      expect((failureResponse.body as { success: boolean }).success).toBe(
        false,
      );

      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      const successRow = await tenantClient.toolInvocation.findFirstOrThrow({
        where: { taskId: task.id, resource: 'host-8-success' },
      });
      const failureRow = await tenantClient.toolInvocation.findFirstOrThrow({
        where: { taskId: task.id, resource: 'host-8-failure' },
      });

      expect(successRow.status).toBe('SUCCESS');
      expect(successRow.errorMessage).toBeNull();
      expect(failureRow.status).toBe('FAILURE');
      expect(failureRow.errorMessage).toBe('HTTP 503');

      // Never the raw request/response payload markers -- only a short
      // shape/summary (see ToolInvocation's schema doc comment).
      expect(JSON.stringify(successRow)).not.toContain(
        'raw-request-payload-marker',
      );
      expect(JSON.stringify(failureRow)).not.toContain(
        'raw-response-payload-marker',
      );
    } finally {
      await fixture.stop();
    }
  }, 30_000);
});
