import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
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
import type { AppConfig } from '../src/config/env.validation';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import { AuthorizationService } from '../src/authorization/authorization.service';
import { OpenFgaClientService } from '../src/authorization/openfga-client.service';
import { TaskGrantSyncService } from '../src/authorization/task-grant-sync.service';
import { TasksService } from '../src/tasks/tasks.service';
import type { AuditService } from '../src/audit/audit.service';
import { PolicyEngine } from '../src/policy/policy-engine.service';
import { RiskEngine } from '../src/risk/risk-engine.service';
import { ToolRegistryService } from '../src/tools/tool-registry.service';
import type { KillSwitchService } from '../src/kill-switches/kill-switch.service';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';

/**
 * Mandatory Phase 5 (Tasks, Delegation & OpenFGA) scenarios — design
 * spec's "Testing" section — run against a real HTTP server, real local
 * Postgres, real local Keycloak, real local OpenBao, and real local
 * OpenFGA (`pnpm infra:up`). Nothing here mocks the authorization decision
 * path: every agent-side call goes through the real `@manar/sdk-node`
 * `ManarAgent` over a real mTLS connection, and every check ultimately
 * hits a real running OpenFGA server.
 */
describe('Tasks, delegation & OpenFGA (e2e)', () => {
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

  const ADMIN_USERNAME = `task-admin-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `task-${label}-${randomUUID().slice(0, 8)}`;
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
      })
      .expect(201);
    return response.body as { id: string; status: string; expiresAt: string };
  }

  async function revokeTask(taskId: string): Promise<void> {
    await request(humanApp.getHttpServer() as App)
      .post(`/tasks/${taskId}/revoke`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ reason: 'e2e test revocation' })
      .expect(201);
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
      name: 'Task Delegation Test Tenant',
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

  it('1. the assigned agent performs a granted action -> ALLOW', async () => {
    const agent = await createEnrolledAgent('allow');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(decision).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  it('2. the assigned agent attempts an action outside task scope -> DENY', async () => {
    const agent = await createEnrolledAgent('out-of-scope');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const decision = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'fs',
      actionId: 'write',
      resource: 'anything',
    });
    expect(decision.decision).toBe('DENY');
    if (decision.decision === 'DENY') {
      expect(decision.reason).toBe('not_authorized');
    }
  }, 30_000);

  it('3. a different (non-assigned) agent cannot use the task -> DENY', async () => {
    const owner = await createEnrolledAgent('owner');
    const stranger = await createEnrolledAgent('stranger');
    const task = await createTask({
      assignedAgentId: owner.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const decision = await stranger.manar.authorize({
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(decision).toEqual<AuthorizeDecision>({
      decision: 'DENY',
      reason: 'not_assigned_agent',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  it('4. delegation requesting a grant the parent does not hold -> rejected, nothing persisted', async () => {
    const parentAgent = await createEnrolledAgent('deleg-reject-parent');
    const parentTask = await createTask({
      assignedAgentId: parentAgent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const agentCountBefore = await tenantClient.agent.count();
    const taskCountBefore = await tenantClient.task.count();

    const childSlug = uniqueSlug('deleg-reject-child');
    await expect(
      parentAgent.manar.delegateTask(parentTask.id, {
        childAgentSlug: childSlug,
        name: 'Should never exist',
        // "write" was never granted to the parent -- must be rejected.
        allowedToolActions: [{ toolId: 'fs', actionId: 'write' }],
        allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      }),
    ).rejects.toThrow();

    const agentCountAfter = await tenantClient.agent.count();
    const taskCountAfter = await tenantClient.task.count();
    expect(agentCountAfter).toBe(agentCountBefore);
    expect(taskCountAfter).toBe(taskCountBefore);

    const childAgent = await tenantClient.agent.findUnique({
      where: { slug: childSlug },
    });
    expect(childAgent).toBeNull();
  }, 30_000);

  it('5. delegation requesting a strict subset succeeds; child agent enrolls and can perform only its narrower grant', async () => {
    const parentAgent = await createEnrolledAgent('deleg-subset-parent');
    const parentTask = await createTask({
      assignedAgentId: parentAgent.agentId,
      allowedToolActions: [
        { toolId: 'fs', actionId: 'read' },
        { toolId: 'fs', actionId: 'write' },
      ],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const childSlug = uniqueSlug('deleg-subset-child');
    const delegation = await parentAgent.manar.delegateTask(parentTask.id, {
      childAgentSlug: childSlug,
      name: 'Narrower child task',
      // Only "read" -- a strict subset of the parent's [read, write].
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    expect(delegation.childTask.parentTaskId).toBe(parentTask.id);
    expect(delegation.childAgent.slug).toBe(childSlug);

    const childIdentityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase-not-for-production',
    );
    const childManar = new ManarAgent({
      endpoint: humanEndpoint,
      mtlsEndpoint: agentMtlsEndpoint,
      identityStore: childIdentityStore,
    });
    await childManar.enroll(delegation.enrollmentToken.token);

    const readDecision = await childManar.authorize({
      taskId: delegation.childTask.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(readDecision).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    // The parent could "write"; the child was never granted it.
    const writeDecision = await childManar.authorize({
      taskId: delegation.childTask.id,
      toolId: 'fs',
      actionId: 'write',
      resource: 'anything',
    });
    expect(writeDecision.decision).toBe('DENY');
  }, 30_000);

  it('5b. delegation cannot raise riskCeiling or maxExecutions above the parent; omitted values are clamped', async () => {
    const parentAgent = await createEnrolledAgent('deleg-limits-parent');
    const parentTask = await createTask({
      assignedAgentId: parentAgent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      maxExecutions: 2,
    });
    const base = {
      name: 'Limits child',
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    };

    // The parent's riskCeiling is the default 20.
    for (const excess of [
      { riskCeiling: 21 },
      { maxExecutions: 3 },
      { maxExecutions: null },
    ]) {
      await expect(
        parentAgent.manar.delegateTask(parentTask.id, {
          ...base,
          ...excess,
          childAgentSlug: uniqueSlug('deleg-limits-reject'),
        }),
      ).rejects.toThrow(/exceeds the parent task's/);
    }

    const delegation = await parentAgent.manar.delegateTask(parentTask.id, {
      ...base,
      childAgentSlug: uniqueSlug('deleg-limits-child'),
    });
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const childTask = await tenantClient.task.findUniqueOrThrow({
      where: { id: delegation.childTask.id },
    });
    expect(childTask).toMatchObject({ riskCeiling: 20, maxExecutions: 2 });
  }, 30_000);

  it('6. privilege amplification: direct out-of-grant authorize, and a second delegation trying to broaden scope, both DENY/rejected', async () => {
    const parentAgent = await createEnrolledAgent('amplify-parent');
    const parentTask = await createTask({
      assignedAgentId: parentAgent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const childSlug = uniqueSlug('amplify-child');
    const delegation = await parentAgent.manar.delegateTask(parentTask.id, {
      childAgentSlug: childSlug,
      name: 'Amplification test child',
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const childIdentityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase-not-for-production',
    );
    const childManar = new ManarAgent({
      endpoint: humanEndpoint,
      mtlsEndpoint: agentMtlsEndpoint,
      identityStore: childIdentityStore,
    });
    await childManar.enroll(delegation.enrollmentToken.token);

    // (a) Direct attempt to authorize an action never granted to the
    // child (also never granted to the parent -- a genuine escalation
    // attempt, not just an unrelated denial).
    const directAttempt = await childManar.authorize({
      taskId: delegation.childTask.id,
      toolId: 'fs',
      actionId: 'delete',
      resource: 'anything',
    });
    expect(directAttempt.decision).toBe('DENY');

    // (b) The child agent tries to delegate a grandchild with a BROADER
    // grant than what it itself effectively holds ("delete", which
    // neither the child nor the parent ever held).
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const agentCountBefore = await tenantClient.agent.count();

    const grandchildSlug = uniqueSlug('amplify-grandchild');
    await expect(
      childManar.delegateTask(delegation.childTask.id, {
        childAgentSlug: grandchildSlug,
        name: 'Should never exist',
        allowedToolActions: [{ toolId: 'fs', actionId: 'delete' }],
        allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      }),
    ).rejects.toThrow();

    const agentCountAfter = await tenantClient.agent.count();
    expect(agentCountAfter).toBe(agentCountBefore);
  }, 30_000);

  it('7. revocation cascade: revoking the parent immediately denies the child, with no cascade write to the child', async () => {
    const parentAgent = await createEnrolledAgent('cascade-parent');
    const parentTask = await createTask({
      assignedAgentId: parentAgent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const childSlug = uniqueSlug('cascade-child');
    const delegation = await parentAgent.manar.delegateTask(parentTask.id, {
      childAgentSlug: childSlug,
      name: 'Cascade test child',
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    const childIdentityStore = new FileIdentityStore(
      `/tmp/manar-sdk-test-${randomUUID()}.identity`,
      'test-passphrase-not-for-production',
    );
    const childManar = new ManarAgent({
      endpoint: humanEndpoint,
      mtlsEndpoint: agentMtlsEndpoint,
      identityStore: childIdentityStore,
    });
    await childManar.enroll(delegation.enrollmentToken.token);

    const authorizeRequest = {
      taskId: delegation.childTask.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };

    // Works once, before revocation.
    const before = await childManar.authorize(authorizeRequest);
    expect(before).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    // Revoke the PARENT -- never the child.
    await revokeTask(parentTask.id);

    // The exact same request, completely unchanged, now denies.
    const after = await childManar.authorize(authorizeRequest);
    expect(after.decision).toBe('DENY');
    expect((after as { reason: string }).reason).toBe(
      'ancestor_task_status_revoked',
    );

    // Proves this wasn't a cascade write to the child: its row is
    // untouched, still ACTIVE.
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const childRow = await tenantClient.task.findUniqueOrThrow({
      where: { id: delegation.childTask.id },
    });
    expect(childRow.status).toBe('ACTIVE');
  }, 30_000);

  it('8. an expired task denies even though its OpenFGA tuples still exist', async () => {
    const agent = await createEnrolledAgent('expired');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
    });

    // Confirm it works before backdating.
    const before = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(before).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    await tenantClient.task.update({
      where: { id: task.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const after = await agent.manar.authorize({
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    });
    expect(after).toEqual<AuthorizeDecision>({
      decision: 'DENY',
      reason: 'task_outside_time_window',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  it('9. maxExecutions exhausted denies on the next attempt', async () => {
    const agent = await createEnrolledAgent('max-exec');
    const task = await createTask({
      assignedAgentId: agent.agentId,
      allowedToolActions: [{ toolId: 'fs', actionId: 'read' }],
      allowedResourceSelectors: [{ toolId: 'fs', pattern: '*' }],
      maxExecutions: 1,
    });

    const request = {
      taskId: task.id,
      toolId: 'fs',
      actionId: 'read',
      resource: 'anything',
    };

    const first = await agent.manar.authorize(request);
    expect(first).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    const second = await agent.manar.authorize(request);
    expect(second).toEqual<AuthorizeDecision>({
      decision: 'DENY',
      reason: 'task_execution_limit_reached',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);

  it('10. OpenFGA outage: authorize fails closed, never ALLOW, against a genuinely unreachable OpenFGA endpoint', async () => {
    const agent = await createEnrolledAgent('outage');
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

    // Confirm it genuinely works against the real, healthy app/OpenFGA
    // first, so the outage result below is a meaningful before/after
    // comparison, not just "it was always going to deny".
    const healthy = await agent.manar.authorize(authorizeRequest);
    expect(healthy).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });

    // Exercises the REAL AuthorizationService/OpenFgaClientService/
    // TasksService classes directly (no HTTP layer, no mocking of the
    // decision-making logic) wired to a genuinely unreachable OpenFGA
    // address -- a real TCP connection failure, not a simulated one.
    //
    // This is deliberately NOT "boot a second AgentMtlsAppModule with
    // OPENFGA_API_URL overridden": @nestjs/config's `ConfigModule.forRoot()`
    // is invoked once, synchronously, as an argument to the `@Module()`
    // decorator on `AppConfigModule` -- i.e. at module *import* time (the
    // first time `config.module.ts` is `require()`d by Node, which already
    // happened via this file's own top-level `import { AppModule } ...`,
    // long before any test body runs). Every subsequent
    // `Test.createTestingModule({ imports: [AgentMtlsAppModule] })` call
    // reuses that same cached, already-validated config -- mutating
    // `process.env` at test-run time has no effect on it. Constructing the
    // real service classes directly sidesteps that entirely, and is also
    // simpler and faster than a second full HTTPS listener.
    //
    // Also deliberately NOT "stop the shared local OpenFGA container": this
    // suite runs alongside other e2e spec files under one `vitest run`
    // (file-level parallelism), and CI has no Docker available to control
    // a container with in the first place (see .gitlab-ci.yml -- CI runs
    // the OpenFGA binary directly, not via Docker). A second, isolated
    // client instance pointed at a real unreachable address proves the
    // same fail-closed behavior just as genuinely, portably, in both
    // environments, without touching anything shared.
    const fakeConfigService = {
      get: (key: string) => {
        const values: Record<string, string> = {
          OPENFGA_API_URL: 'http://127.0.0.1:1', // no listener -- a real, immediate ECONNREFUSED
          OPENFGA_STORE_NAME: 'manar-unreachable-test',
          OPENFGA_MODEL_FILE_PATH: 'src/authorization/model/manar.fga',
        };
        return values[key];
      },
    } as unknown as ConfigService<AppConfig, true>;

    const brokenOpenFga = new OpenFgaClientService(fakeConfigService);
    await brokenOpenFga.onModuleInit(); // resilient by design -- logs and leaves itself "not ready", does not throw (see its own doc comment)
    expect(brokenOpenFga.storeId).toBeNull();

    const tasksServiceForBrokenClient = new TasksService(
      new TaskGrantSyncService(brokenOpenFga),
      {
        recordSafely: () => Promise.resolve(undefined),
      } as unknown as AuditService,
    );
    // PolicyEngine/RiskEngine (Phase 6) are never actually reached in this
    // scenario -- OpenFGA denies first (step 5), well before either would
    // run -- but AuthorizationService's constructor still needs real
    // instances, same as tasksServiceForBrokenClient above. RiskEngine's
    // ToolRegistryService/AiAdvisoryClient dependencies (Phase 7b/10b) are
    // likewise never actually queried here for the same reason -- a real
    // ToolRegistryService with no tenant client ever passed to it, and an
    // unused AiAdvisoryClient stub, are enough to satisfy the constructor.
    const brokenAuthorizationService = new AuthorizationService(
      tasksServiceForBrokenClient,
      brokenOpenFga,
      new PolicyEngine(new ToolRegistryService()),
      new RiskEngine(tasksServiceForBrokenClient, new ToolRegistryService()),
      {
        recordSafely: () => Promise.resolve(undefined),
      } as unknown as AuditService,
      {
        checkAll: () => Promise.resolve({ killed: false }),
      } as unknown as KillSwitchService,
    );

    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const duringOutage = await brokenAuthorizationService.authorize(
      tenantClient,
      tenant.id,
      agent.agentId,
      authorizeRequest,
    );
    expect(duringOutage.decision).toBe('DENY');
    expect((duringOutage as { reason: string }).reason).toBe(
      'authorization_backend_unavailable',
    );

    // The real, healthy app/OpenFGA is completely unaffected -- the exact
    // same request against it still succeeds, proving this wasn't a
    // permanent break of anything shared.
    const afterOutage = await agent.manar.authorize(authorizeRequest);
    expect(afterOutage).toEqual<AuthorizeDecision>({
      decision: 'ALLOW',
      decisionId: expect.any(String) as string,
    });
  }, 30_000);
});
