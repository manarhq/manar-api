import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import { AuditReindexService } from '../src/audit/opensearch/audit-reindex.service';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';

/**
 * Phase 11b Part 1 — the mandatory "Testing" scenarios for the new list/
 * search endpoints (see
 * docs/superpowers/specs/2026-08-19-phase11b-list-endpoints-core-pages-design.md):
 * pagination, filters, and — the hard requirement — every new list
 * endpoint is provably tenant-scoped, reusing this codebase's established
 * two-tenant isolation pattern (`test/auth.e2e-spec.ts`,
 * `test/kill-switches.e2e-spec.ts`).
 *
 * Deliberately does NOT boot `AgentMtlsAppModule`/`WorkerAppModule`/a
 * Temporal worker: every resource this file lists is created either
 * through its own real, lightweight human-facing `POST` endpoint (Agent,
 * Task, Policy, WebhookEndpoint, KillSwitch), or — for the two resources
 * with no minimal human-facing create path that doesn't also require a
 * full mTLS-agent-enrollment/Temporal-approval-workflow round trip (Tool,
 * ApprovalRequest) — direct `tenantClient` writes, the same documented
 * exception this codebase's own e2e suites already establish (e.g.
 * `test/kill-switches.e2e-spec.ts`'s AgentGroup fixture, or the many
 * `tenantClient.tool.create(...)` fixtures across the existing suite).
 * This suite is about the list/search *endpoints* — pagination, filters,
 * tenant scoping — not re-proving the approval workflow or tool
 * invocation pipelines, which are already covered elsewhere.
 */
describe('List/search endpoints (e2e)', () => {
  let humanApp: NestFastifyApplication;
  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;
  let auditReindexService: AuditReindexService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;

  let tenantA: ProvisionedTenant;
  let tenantB: ProvisionedTenant;
  let tokenA: string;
  let tokenB: string;

  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `le-${label}-${randomUUID().slice(0, 8)}`;
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
  ): Promise<{ tenant: ProvisionedTenant; token: string }> {
    const provisioned = await provisioning.provisionTenant({
      slug: uniqueSlug(slugLabel),
      name: `List Endpoints Test Tenant ${slugLabel}`,
    });
    if (!provisioned.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }
    const username = `le-admin-${randomUUID().slice(0, 8)}`;
    const clientSecretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: provisioned.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    const userId = await createRealmUser(provisioned.keycloakRealm, {
      username,
      email: `${username}@example.test`,
      password: USER_PASSWORD,
    });
    // TENANT_OWNER alone is allowed by every controller this suite calls
    // (Agents/Tasks/Policies/Approvals/KillSwitches/Webhooks/Tools/Audit)
    // — see each controller's own @RequireRole(...).
    await assignRealmRole(provisioned.keycloakRealm, userId, 'TENANT_OWNER');
    const token = await getUserToken({
      realm: provisioned.keycloakRealm,
      clientId: provisioned.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username,
      password: USER_PASSWORD,
    });
    return { tenant: provisioned, token };
  }

  async function createAgent(
    token: string,
    slugLabel: string,
  ): Promise<{ id: string; slug: string }> {
    const slug = uniqueSlug(slugLabel);
    const res = await request(humanApp.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${token}`)
      .send({ slug, displayName: `Agent ${slug}` })
      .expect(201);
    return { id: (res.body as { id: string }).id, slug };
  }

  async function createTask(
    token: string,
    assignedAgentId: string,
    overrides: Partial<{ name: string; expiresAt: string }> = {},
  ): Promise<{ id: string; status: string }> {
    const res = await request(humanApp.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: overrides.name ?? `Task ${randomUUID().slice(0, 8)}`,
        assignedAgentId,
        allowedToolActions: [],
        allowedResourceSelectors: [],
        forbiddenActions: [],
        expiresAt:
          overrides.expiresAt ?? new Date(Date.now() + 3_600_000).toISOString(),
        riskCeiling: 20,
      })
      .expect(201);
    return res.body as { id: string; status: string };
  }

  async function createPolicy(token: string): Promise<{ id: string }> {
    const res = await request(humanApp.getHttpServer() as App)
      .post('/policies')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: `Policy ${randomUUID().slice(0, 8)}`,
        content: {
          rules: [
            {
              toolId: '*',
              actionId: '*',
              resourcePattern: '*',
              effect: 'ALLOW',
            },
          ],
        },
      })
      .expect(201);
    return res.body as { id: string };
  }

  async function createWebhook(token: string): Promise<{ id: string }> {
    const res = await request(humanApp.getHttpServer() as App)
      .post('/webhooks')
      .set('Authorization', `Bearer ${token}`)
      .send({
        url: `http://127.0.0.1:9/webhook-${randomUUID().slice(0, 8)}`,
        subscribedEventTypes: ['task.created'],
      })
      .expect(201);
    return res.body as { id: string };
  }

  async function registerTool(
    tenantId: string,
    overrides: Partial<{ enabled: boolean }> = {},
  ): Promise<{ id: string; name: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenantId);
    return tenantClient.tool.create({
      data: {
        name: `tool-${randomUUID().slice(0, 8)}`,
        type: 'TEST',
        baseEndpoint: 'http://127.0.0.1:9/tool',
        protocol: 'HTTP',
        credentialReference: { provider: 'ENV', reference: 'PATH' },
        enabled: overrides.enabled ?? true,
        actions: {
          create: [
            {
              name: 'do_thing',
              riskBaseScore: 10,
              mutating: false,
              destructive: false,
            },
          ],
        },
      },
    });
  }

  async function createApprovalRequest(
    tenantId: string,
    taskId: string,
    agentId: string,
    overrides: Partial<{
      status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED';
    }> = {},
  ): Promise<{ id: string }> {
    const tenantClient = await tenantDatabaseManager.getClient(tenantId);
    return tenantClient.approvalRequest.create({
      data: {
        taskId,
        agentId,
        toolId: 'test-tool',
        actionId: 'test-action',
        resource: 'test-resource',
        params: {},
        riskScore: 55,
        policyVersionId: null,
        status: overrides.status ?? 'PENDING',
        expiresAt: new Date(Date.now() + 1_800_000),
        temporalWorkflowId: `test-wf-${randomUUID()}`,
      },
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

    control = humanApp.get(ControlPrismaService);
    tenantDatabaseManager = humanApp.get(TenantDatabaseManager);
    provisioning = humanApp.get(TenantProvisioningService);
    auditReindexService = humanApp.get(AuditReindexService);

    const a = await provisionTestTenant('a');
    tenantA = a.tenant;
    tokenA = a.token;
    const b = await provisionTestTenant('b');
    tenantB = b.tenant;
    tokenB = b.token;
  }, 120_000);

  afterAll(async () => {
    await cleanupTenant(tenantA);
    await cleanupTenant(tenantB);
    await humanApp.close();
  }, 60_000);

  // -----------------------------------------------------------------------
  // Pagination — proven thoroughly on Agents; every other resource's list
  // endpoint shares the exact same `toCursorPage`/`cursorWhereClause`
  // implementation (src/common/pagination/cursor-pagination.ts), so this
  // is the one place cursor correctness itself needs a real, careful test.
  // -----------------------------------------------------------------------

  describe('pagination', () => {
    it('walks every created agent exactly once across cursor pages, respecting the requested limit', async () => {
      const createdIds: string[] = [];
      for (let i = 0; i < 5; i += 1) {
        const { id } = await createAgent(tokenA, `page-${i}`);
        createdIds.push(id);
      }

      const seenCounts = new Map<string, number>();
      let cursor: string | undefined;
      let pages = 0;
      for (;;) {
        const query: Record<string, string> = { limit: '2' };
        if (cursor) query.cursor = cursor;
        const res = await request(humanApp.getHttpServer() as App)
          .get('/agents')
          .query(query)
          .set('Authorization', `Bearer ${tokenA}`)
          .expect(200);
        const body = res.body as {
          items: { id: string }[];
          nextCursor: string | null;
        };
        expect(body.items.length).toBeLessThanOrEqual(2);
        for (const item of body.items) {
          seenCounts.set(item.id, (seenCounts.get(item.id) ?? 0) + 1);
        }
        pages += 1;
        if (!body.nextCursor || pages > 50) {
          cursor = undefined;
          break;
        }
        cursor = body.nextCursor;
      }

      for (const id of createdIds) {
        expect(seenCounts.get(id)).toBe(1);
      }
    });

    it('GET /tasks supports the status and assignedAgentId filters', async () => {
      const agent = await createAgent(tokenA, 'task-filter');
      const task = await createTask(tokenA, agent.id);
      await request(humanApp.getHttpServer() as App)
        .post(`/tasks/${task.id}/revoke`)
        .set('Authorization', `Bearer ${tokenA}`)
        .send({ reason: 'test revoke' })
        .expect(201);

      const byAgent = await request(humanApp.getHttpServer() as App)
        .get('/tasks')
        .query({ assignedAgentId: agent.id })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const byAgentBody = byAgent.body as { items: { id: string }[] };
      expect(byAgentBody.items.some((t) => t.id === task.id)).toBe(true);
      expect(byAgentBody.items.every((t) => t.id === task.id)).toBe(true);

      const byStatus = await request(humanApp.getHttpServer() as App)
        .get('/tasks')
        .query({ status: 'REVOKED', assignedAgentId: agent.id })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const byStatusBody = byStatus.body as {
        items: { id: string; status: string }[];
      };
      expect(byStatusBody.items.map((t) => t.id)).toContain(task.id);
      for (const item of byStatusBody.items) {
        expect(item.status).toBe('REVOKED');
      }
    });

    it('GET /agents supports the status filter', async () => {
      const agent = await createAgent(tokenA, 'agent-filter');
      const res = await request(humanApp.getHttpServer() as App)
        .get('/agents')
        .query({ status: 'PENDING_ENROLLMENT' })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const body = res.body as { items: { id: string; status: string }[] };
      expect(body.items.map((a) => a.id)).toContain(agent.id);
      for (const item of body.items) {
        expect(item.status).toBe('PENDING_ENROLLMENT');
      }
    });

    it('GET /approvals supports the status filter', async () => {
      const agent = await createAgent(tokenA, 'appr-filter');
      const task = await createTask(tokenA, agent.id);
      const approval = await createApprovalRequest(
        tenantA.id,
        task.id,
        agent.id,
        { status: 'PENDING' },
      );

      const res = await request(humanApp.getHttpServer() as App)
        .get('/approvals')
        .query({ status: 'PENDING' })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const body = res.body as { items: { id: string; status: string }[] };
      expect(body.items.map((a) => a.id)).toContain(approval.id);
      for (const item of body.items) {
        expect(item.status).toBe('PENDING');
      }
    });

    it('GET /webhooks and GET /tools support the enabled filter, and GET /webhooks returns the new {items,nextCursor} envelope', async () => {
      const webhook = await createWebhook(tokenA);
      const disabledTool = await registerTool(tenantA.id, { enabled: false });

      const webhookRes = await request(humanApp.getHttpServer() as App)
        .get('/webhooks')
        .query({ enabled: 'true' })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const webhookBody = webhookRes.body as {
        items: { id: string; enabled: boolean }[];
        nextCursor: string | null;
      };
      expect(Array.isArray(webhookBody.items)).toBe(true);
      expect('nextCursor' in webhookBody).toBe(true);
      expect(webhookBody.items.map((w) => w.id)).toContain(webhook.id);
      for (const item of webhookBody.items) expect(item.enabled).toBe(true);

      const toolRes = await request(humanApp.getHttpServer() as App)
        .get('/tools')
        .query({ enabled: 'false' })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const toolBody = toolRes.body as {
        items: { id: string; enabled: boolean; actions: { name: string }[] }[];
      };
      expect(toolBody.items.map((t) => t.id)).toContain(disabledTool.id);
      const found = toolBody.items.find((t) => t.id === disabledTool.id);
      expect(found?.enabled).toBe(false);
      expect(found?.actions.some((a) => a.name === 'do_thing')).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // Tenant isolation — the hard requirement (Section 8, this phase's
  // "Testing" section): every new list endpoint must never leak another
  // tenant's rows.
  // -----------------------------------------------------------------------

  describe('tenant isolation', () => {
    it("GET /agents never returns another tenant's agents", async () => {
      const agentA = await createAgent(tokenA, 'iso');
      const resB = await request(humanApp.getHttpServer() as App)
        .get('/agents')
        .query({ limit: '100' })
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);
      const bodyB = resB.body as { items: { id: string }[] };
      expect(bodyB.items.map((a) => a.id)).not.toContain(agentA.id);
    });

    it("GET /tasks never returns another tenant's tasks", async () => {
      const agentA = await createAgent(tokenA, 'iso-task');
      const taskA = await createTask(tokenA, agentA.id);
      const resB = await request(humanApp.getHttpServer() as App)
        .get('/tasks')
        .query({ limit: '100' })
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);
      const bodyB = resB.body as { items: { id: string }[] };
      expect(bodyB.items.map((t) => t.id)).not.toContain(taskA.id);
    });

    it("GET /policies never returns another tenant's policies", async () => {
      const policyA = await createPolicy(tokenA);
      const resB = await request(humanApp.getHttpServer() as App)
        .get('/policies')
        .query({ limit: '100' })
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);
      const bodyB = resB.body as { items: { id: string }[] };
      expect(bodyB.items.map((p) => p.id)).not.toContain(policyA.id);
    });

    it("GET /webhooks never returns another tenant's webhook endpoints", async () => {
      const webhookA = await createWebhook(tokenA);
      const resB = await request(humanApp.getHttpServer() as App)
        .get('/webhooks')
        .query({ limit: '100' })
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);
      const bodyB = resB.body as { items: { id: string }[] };
      expect(bodyB.items.map((w) => w.id)).not.toContain(webhookA.id);
    });

    it("GET /tools never returns another tenant's tools", async () => {
      const toolA = await registerTool(tenantA.id);
      const resB = await request(humanApp.getHttpServer() as App)
        .get('/tools')
        .query({ limit: '100' })
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);
      const bodyB = resB.body as { items: { id: string }[] };
      expect(bodyB.items.map((t) => t.id)).not.toContain(toolA.id);
    });

    it("GET /approvals never returns another tenant's approval requests", async () => {
      const agentA = await createAgent(tokenA, 'iso-appr');
      const taskA = await createTask(tokenA, agentA.id);
      const approvalA = await createApprovalRequest(
        tenantA.id,
        taskA.id,
        agentA.id,
      );
      const resB = await request(humanApp.getHttpServer() as App)
        .get('/approvals')
        .query({ limit: '100' })
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);
      const bodyB = resB.body as { items: { id: string }[] };
      expect(bodyB.items.map((a) => a.id)).not.toContain(approvalA.id);
    });

    it("GET /kill-switches never returns another tenant's kill switches", async () => {
      const agentA = await createAgent(tokenA, 'iso-ks');
      const activateRes = await request(humanApp.getHttpServer() as App)
        .post(`/agents/${agentA.id}/kill-switch`)
        .set('Authorization', `Bearer ${tokenA}`)
        .send({ reason: 'isolation test' })
        .expect(201);
      const killSwitchIdA = (activateRes.body as { id: string }).id;

      const resB = await request(humanApp.getHttpServer() as App)
        .get('/kill-switches')
        .query({ limit: '100' })
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);
      const bodyB = resB.body as { items: { id: string }[] };
      expect(bodyB.items.map((k) => k.id)).not.toContain(killSwitchIdA);
    });

    it("GET /audit never returns another tenant's events, even when filtered by that tenant's own real taskId", async () => {
      const agentA = await createAgent(tokenA, 'iso-audit');
      const taskA = await createTask(tokenA, agentA.id);
      const tenantClientA = await tenantDatabaseManager.getClient(tenantA.id);
      await auditReindexService.reindexTenant(tenantClientA, tenantA.id);

      const resAsA = await request(humanApp.getHttpServer() as App)
        .get('/audit')
        .query({ taskId: taskA.id })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const bodyAsA = resAsA.body as {
        items: { eventType: string; taskId?: string }[];
      };
      expect(
        bodyAsA.items.some(
          (e) => e.eventType === 'task.created' && e.taskId === taskA.id,
        ),
      ).toBe(true);

      // Same taskId filter, different tenant's own token -- the mandatory
      // tenantId term filter (AuditSearchService.search) must still apply
      // regardless of any other filter, or this would leak tenant A's
      // audit history to tenant B.
      const resAsB = await request(humanApp.getHttpServer() as App)
        .get('/audit')
        .query({ taskId: taskA.id })
        .set('Authorization', `Bearer ${tokenB}`)
        .expect(200);
      const bodyAsB = resAsB.body as { items: unknown[] };
      expect(bodyAsB.items).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // GET /audit — cross-checked against a known seeded set of events.
  // -----------------------------------------------------------------------

  describe('audit search', () => {
    it('finds a real recorded event by eventType + taskId, and pagination shape is correct', async () => {
      const agent = await createAgent(tokenA, 'audit-search');
      const task = await createTask(tokenA, agent.id);
      const tenantClientA = await tenantDatabaseManager.getClient(tenantA.id);
      await auditReindexService.reindexTenant(tenantClientA, tenantA.id);

      const res = await request(humanApp.getHttpServer() as App)
        .get('/audit')
        .query({ eventType: 'task.created', taskId: task.id })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const body = res.body as {
        items: {
          eventId: string;
          eventType: string;
          taskId?: string;
          data: unknown;
        }[];
        nextCursor: string | null;
      };
      expect('nextCursor' in body).toBe(true);
      const match = body.items.find(
        (e) => e.eventType === 'task.created' && e.taskId === task.id,
      );
      expect(match).toBeDefined();
    });

    it('rejects a malformed riskMin/riskMax with 400', async () => {
      await request(humanApp.getHttpServer() as App)
        .get('/audit')
        .query({ riskMin: 'not-a-number' })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(400);
    });
  });

  // -----------------------------------------------------------------------
  // Tenant OIDC config resolution — the Keycloak client-secret workaround
  // fix.
  // -----------------------------------------------------------------------

  describe('GET /tenants/:slug/oidc-config and /oidc-client-secret', () => {
    it('the public oidc-config endpoint is unauthenticated, returns the real issuer/client info, and never includes the client secret', async () => {
      const res = await request(humanApp.getHttpServer() as App)
        .get(`/tenants/${tenantA.slug}/oidc-config`)
        .expect(200);
      const body = res.body as Record<string, unknown>;
      expect(body.slug).toBe(tenantA.slug);
      expect(body.realm).toBe(tenantA.keycloakRealm);
      expect(body.issuerUrl).toBe(tenantA.keycloakIssuerUrl);
      expect(body.clientId).toBe(tenantA.keycloakClientId);
      expect(typeof body.authorizationEndpoint).toBe('string');
      expect(typeof body.tokenEndpoint).toBe('string');
      expect(typeof body.jwksUri).toBe('string');
      // The one hard security invariant this endpoint must never regress:
      // no field named/containing the secret anywhere in the response.
      expect(JSON.stringify(body)).not.toContain('clientSecret');
      expect('clientSecret' in body).toBe(false);
    });

    it('404s for an unknown/unprovisioned tenant slug', async () => {
      await request(humanApp.getHttpServer() as App)
        .get(`/tenants/no-such-tenant-${randomUUID()}/oidc-config`)
        .expect(404);
    });

    it('the client-secret endpoint refuses a request with no X-Manar-Bff-Token header', async () => {
      await request(humanApp.getHttpServer() as App)
        .get(`/tenants/${tenantA.slug}/oidc-client-secret`)
        .expect(401);
    });

    it('the client-secret endpoint refuses a request with the wrong token', async () => {
      await request(humanApp.getHttpServer() as App)
        .get(`/tenants/${tenantA.slug}/oidc-client-secret`)
        .set('X-Manar-Bff-Token', 'not-the-real-token')
        .expect(401);
    });

    it('the client-secret endpoint returns the real secret to a caller presenting the correct service token', async () => {
      const expectedSecret = await control.secretReference.findFirstOrThrow({
        where: { tenantId: tenantA.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
      });
      const realToken =
        process.env.MANAR_BFF_SERVICE_TOKEN ??
        'dev-only-manar-bff-service-token-change-me';

      const res = await request(humanApp.getHttpServer() as App)
        .get(`/tenants/${tenantA.slug}/oidc-client-secret`)
        .set('X-Manar-Bff-Token', realToken)
        .expect(200);
      const body = res.body as { clientSecret: string };
      expect(body.clientSecret).toBe(expectedSecret.reference);
    });
  });
});
