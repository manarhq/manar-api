import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import type { ConfigService } from '@nestjs/config';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import { FileIdentityStore, ManarAgent } from '@manar/sdk-node';
import type { AgentIdentity, AuthorizeDecision } from '@manar/sdk-node';
import { AppModule } from '../src/app.module';
import { AgentMtlsAppModule } from '../src/agent-mtls/agent-mtls-app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import { AiAdvisoryClient } from '../src/ai-advisory/ai-advisory-client.service';
import { AuditReindexService } from '../src/audit/opensearch/audit-reindex.service';
import type { AppConfig } from '../src/config/env.validation';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';
import { FakeAnalysisServiceServer } from './support/fake-analysis-service-server';

/**
 * Phase 10c (RAG, Incident Summarization, Policy Assistant & Audit
 * Investigation) — the design spec's mandatory "Testing" scenarios for the
 * `manar-api` side of this phase:
 *
 *   - manar-ai fully unreachable -> all three new endpoints
 *     (`POST /incidents/summarize`, `POST /policies/suggest`,
 *     `POST /audit/investigate`) degrade to a clear `available: false`
 *     response, never a crash, never fabricated output.
 *   - `POST /policies/suggest`'s output is persisted as `DRAFT` only, and
 *     has zero effect on real authorization decisions until separately
 *     published via the normal
 *     `POST /policies/:id/versions/:versionId/publish` endpoint.
 *   - `POST /audit/investigate` never lets manar-ai see another tenant's
 *     audit data — asserted at the gRPC-request level
 *     (`FakeAnalysisServiceServer.lastInvestigateAuditRequest`), not just
 *     "the endpoint responded 200".
 *
 * Mirrors `test/ai-advisory.e2e-spec.ts`'s `bootAltAgentMtlsApp`/
 * `buildAiAdvisoryClient` pattern (a fresh `AiAdvisoryClient`, DI-overridden
 * per scenario via `overrideProvider`, never an env-var override — see that
 * file's own doc comments for why), applied to `AppModule` (the human-facing
 * app these three endpoints actually live on) instead of
 * `AgentMtlsAppModule`. The one scenario that needs a real authorize
 * decision (the DRAFT-only invariant) also boots `AgentMtlsAppModule`,
 * mirroring `test/policy-risk.e2e-spec.ts`.
 */
describe('Phase 10c: AI Extended Capabilities (e2e)', () => {
  let humanApp: NestFastifyApplication;
  let agentMtlsApp: NestFastifyApplication;
  let humanEndpoint: string;
  let agentMtlsEndpoint: string;

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
    return `p10c-${label}-${randomUUID().slice(0, 8)}`;
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

  async function provisionTenantWithUser(
    label: string,
  ): Promise<{ tenant: ProvisionedTenant; token: string }> {
    const t = await provisioning.provisionTenant({
      slug: uniqueSlug(label),
      name: `Phase 10c Test Tenant ${label}`,
    });
    if (!t.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }
    const secretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: t.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    const username = `p10c-user-${label}-${randomUUID().slice(0, 8)}`;
    const userId = await createRealmUser(t.keycloakRealm, {
      username,
      email: `${username}@example.test`,
      password: USER_PASSWORD,
    });
    // TENANT_OWNER alone satisfies every controller this suite calls
    // (/incidents -- no role gate at all; /policies -- SECURITY_ADMIN/
    // TENANT_OWNER/AI_GOVERNANCE_MANAGER; /audit -- AUDITOR/SECURITY_ADMIN/
    // TENANT_OWNER), same posture test/list-endpoints.e2e-spec.ts already
    // establishes.
    await assignRealmRole(t.keycloakRealm, userId, 'TENANT_OWNER');
    const token = await getUserToken({
      realm: t.keycloakRealm,
      clientId: t.keycloakClientId!,
      clientSecret: secretRef.reference,
      username,
      password: USER_PASSWORD,
    });
    return { tenant: t, token };
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

  interface GrantInput {
    toolId: string;
    actionId: string;
  }
  interface ResourceInput {
    toolId: string;
    pattern: string;
  }

  /** Creates a Task via the real human HTTP API -- generates a real `task.created` AuditEvent (used as retrieval fixture data for the cross-tenant investigate scenario). */
  async function createTask(
    token: string,
    assignedAgentId: string,
    input: {
      allowedToolActions?: GrantInput[];
      allowedResourceSelectors?: ResourceInput[];
      riskCeiling?: number;
    } = {},
  ): Promise<{ id: string; status: string }> {
    const res = await request(humanApp.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${token}`)
      .send({
        name: `Task ${randomUUID().slice(0, 8)}`,
        assignedAgentId,
        allowedToolActions: input.allowedToolActions ?? [],
        allowedResourceSelectors: input.allowedResourceSelectors ?? [],
        forbiddenActions: [],
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        riskCeiling: input.riskCeiling,
      })
      .expect(201);
    return res.body as { id: string; status: string };
  }

  /** Enrolls a real agent (via the real SDK against the real mTLS listener) -- needed only for the DRAFT-only-invariant scenario's real `authorize` round trip. */
  async function createEnrolledAgent(
    token: string,
    slugLabel: string,
  ): Promise<{ agentId: string; identity: AgentIdentity; manar: ManarAgent }> {
    const agent = await createAgent(token, slugLabel);
    const tokenResponse = await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agent.id}/enrollment-tokens`)
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
    return { agentId: agent.id, identity, manar };
  }

  /**
   * Same pattern `test/ai-advisory.e2e-spec.ts`'s `buildAiAdvisoryClient`
   * establishes -- a real `AiAdvisoryClient`, constructed directly (not
   * through DI) with a minimal fake `ConfigService`, so its
   * target/timeout/circuit-breaker can vary per scenario via
   * `overrideProvider` rather than an ineffective env-var override (see
   * that file's own doc comment for why env vars don't work for this).
   */
  function buildAiAdvisoryClient(overrides: {
    grpcTarget: string;
    timeoutMs?: number;
  }): AiAdvisoryClient {
    const values = {
      AI_ADVISORY_GRPC_TARGET: overrides.grpcTarget,
      AI_ADVISORY_TIMEOUT_MS: overrides.timeoutMs ?? 1000,
      AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 3,
      AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
    };
    const configService = {
      get: (key: string) => (values as Record<string, unknown>)[key],
    } as unknown as ConfigService<AppConfig, true>;
    // AI_ADVISORY_PROVIDER left undefined -> never 'anthropic' -> the
    // data-residency gate always short-circuits to "allowed" without
    // dereferencing `control` -- see buildAiAdvisoryClient's identical
    // convention in test/ai-advisory.e2e-spec.ts.
    return new AiAdvisoryClient(configService, control);
  }

  /** Boots a *separate* `AppModule` instance whose `AiAdvisoryClient` is replaced -- mirrors `bootAltAgentMtlsApp` (`test/ai-advisory.e2e-spec.ts`) applied to the human-facing app instead. */
  async function bootAltHumanApp(
    customAiAdvisoryClient: AiAdvisoryClient,
  ): Promise<{ app: NestFastifyApplication }> {
    const fixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    })
      .overrideProvider(AiAdvisoryClient)
      .useValue(customAiAdvisoryClient)
      .compile();
    const app = fixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    return { app };
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
    auditReindexService = humanApp.get(AuditReindexService);

    const a = await provisionTenantWithUser('a');
    tenantA = a.tenant;
    tokenA = a.token;
    const b = await provisionTenantWithUser('b');
    tenantB = b.tenant;
    tokenB = b.token;
  }, 180_000);

  afterAll(async () => {
    await humanApp.close();
    await agentMtlsApp.close();
    if (tenantA) await cleanupTenant(tenantA);
    if (tenantB) await cleanupTenant(tenantB);
    await control.$disconnect();
  }, 60_000);

  // ---------------------------------------------------------------------
  // 1-3. manar-ai fully unreachable -> all three endpoints degrade to a
  // clear `available: false`, never a crash.
  // ---------------------------------------------------------------------
  describe('manar-ai fully unreachable', () => {
    let unreachableApp: NestFastifyApplication;

    beforeAll(async () => {
      const alt = await bootAltHumanApp(
        buildAiAdvisoryClient({
          grpcTarget: '127.0.0.1:1', // nothing listens here
          timeoutMs: 300,
        }),
      );
      unreachableApp = alt.app;
    }, 30_000);

    afterAll(async () => {
      await unreachableApp.close();
    });

    it('1. POST /incidents/summarize returns available:false, never a crash', async () => {
      const res = await request(unreachableApp.getHttpServer() as App)
        .post('/incidents/summarize')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({ description: 'a suspicious login pattern was observed' })
        .expect(201);
      const body = res.body as {
        available: boolean;
        result: unknown;
        contextEventCount: number;
      };
      expect(body.available).toBe(false);
      expect(body.result).toBeNull();
    }, 15_000);

    it('2. POST /policies/suggest returns available:false and creates nothing', async () => {
      const policyName = uniqueSlug('outage-suggested-policy');
      const res = await request(unreachableApp.getHttpServer() as App)
        .post('/policies/suggest')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          naturalLanguageDescription: 'deny everything sensitive',
          policyName,
        })
        .expect(201);
      const body = res.body as {
        available: boolean;
        policyId: string | null;
        version: unknown;
      };
      expect(body.available).toBe(false);
      expect(body.policyId).toBeNull();
      expect(body.version).toBeNull();

      // Nothing was actually persisted -- no Policy with this name exists.
      const list = await request(humanApp.getHttpServer() as App)
        .get('/policies')
        .query({ limit: '100' })
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      const listBody = list.body as { items: { name: string }[] };
      expect(listBody.items.some((p) => p.name === policyName)).toBe(false);
    }, 15_000);

    it('3. POST /audit/investigate returns available:false, never a crash', async () => {
      const res = await request(unreachableApp.getHttpServer() as App)
        .post('/audit/investigate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({ question: 'why was this denied?' })
        .expect(201);
      const body = res.body as { available: boolean; result: unknown };
      expect(body.available).toBe(false);
      expect(body.result).toBeNull();
    }, 15_000);
  });

  // ---------------------------------------------------------------------
  // 4. POST /policies/suggest: DRAFT-only invariant (mandatory).
  // ---------------------------------------------------------------------
  it('4. POST /policies/suggest creates a DRAFT PolicyVersion with zero effect on authorization until separately published', async () => {
    const fakeServer = new FakeAnalysisServiceServer();
    const target = await fakeServer.start();
    const toolId = uniqueSlug('suggest-tool').replace(/-/g, '_');
    const actionId = 'sensitive_action';

    fakeServer.policyDraftResult = {
      rules: [
        {
          name: 'AI-suggested deny',
          toolId,
          actionId,
          resourcePattern: '*',
          effect: 2, // PolicyRuleDraft_Effect.EFFECT_DENY
          riskWeight: 0,
          riskFloor: 0,
          description: 'Suggested by manar-ai for this test',
        },
      ],
      explanation: 'Denying this sensitive action per the description',
      confidence: 0.9,
    };

    const alt = await bootAltHumanApp(
      buildAiAdvisoryClient({ grpcTarget: target }),
    );
    try {
      const policyName = uniqueSlug('draft-only-policy');
      const suggestRes = await request(alt.app.getHttpServer() as App)
        .post('/policies/suggest')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          naturalLanguageDescription: `Deny ${toolId}/${actionId}`,
          policyName,
        })
        .expect(201);
      const suggested = suggestRes.body as {
        available: boolean;
        policyId: string;
        version: { id: string; status: string };
      };
      expect(suggested.available).toBe(true);
      // The one mandatory assertion: freshly suggested, persisted version
      // is DRAFT -- never PUBLISHED.
      expect(suggested.version.status).toBe('DRAFT');

      // Confirm via a completely independent read too (GET /policies/:id
      // never surfaces a DRAFT as the "current" version).
      const getPolicy = await request(humanApp.getHttpServer() as App)
        .get(`/policies/${suggested.policyId}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);
      expect(
        (getPolicy.body as { currentVersion: unknown }).currentVersion,
      ).toBeNull();

      // Real authorize round trip: a task granting exactly this action via
      // OpenFGA/task-scope, with no PUBLISHED policy yet -> ALLOW (the
      // DRAFT has zero effect, proven against the real PolicyEngine, not
      // just documentation).
      const agent = await createEnrolledAgent(tokenA, 'draft-only');
      const task = await createTask(tokenA, agent.agentId, {
        allowedToolActions: [{ toolId, actionId }],
        allowedResourceSelectors: [{ toolId, pattern: '*' }],
      });

      const beforePublish = await agent.manar.authorize({
        taskId: task.id,
        toolId,
        actionId,
        resource: 'anything',
      });
      expect(beforePublish).toEqual<AuthorizeDecision>({ decision: 'ALLOW' });

      // Now publish it through the normal, separate publish endpoint.
      await request(humanApp.getHttpServer() as App)
        .post(
          `/policies/${suggested.policyId}/versions/${suggested.version.id}/publish`,
        )
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(201);

      const afterPublish = await agent.manar.authorize({
        taskId: task.id,
        toolId,
        actionId,
        resource: 'anything',
      });
      expect(afterPublish.decision).toBe('DENY');
      if (afterPublish.decision === 'DENY') {
        expect(afterPublish.reason).toBe('policy_denied');
      }
    } finally {
      await alt.app.close();
      await fakeServer.stop();
    }
  }, 60_000);

  // ---------------------------------------------------------------------
  // 5. POST /audit/investigate: cross-tenant-data invariant (mandatory).
  // ---------------------------------------------------------------------
  it("5. POST /audit/investigate's retrieved context never contains another tenant's audit data, asserted at the gRPC-request level", async () => {
    const fakeServer = new FakeAnalysisServiceServer();
    const target = await fakeServer.start();
    fakeServer.auditInvestigationResult = {
      answer: 'test answer',
      citations: [],
      confidence: 0.8,
      explanation: 'test',
    };

    const alt = await bootAltHumanApp(
      buildAiAdvisoryClient({ grpcTarget: target }),
    );
    try {
      const agentA = await createAgent(tokenA, 'investigate-a');
      const taskA = await createTask(tokenA, agentA.id);
      const agentB = await createAgent(tokenB, 'investigate-b');
      const taskB = await createTask(tokenB, agentB.id);

      const tenantClientA = await tenantDatabaseManager.getClient(tenantA.id);
      const tenantClientB = await tenantDatabaseManager.getClient(tenantB.id);
      await auditReindexService.reindexTenant(tenantClientA, tenantA.id);
      await auditReindexService.reindexTenant(tenantClientB, tenantB.id);

      const res = await request(alt.app.getHttpServer() as App)
        .post('/audit/investigate')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          question: 'What tasks were recently created?',
          eventType: 'task.created',
          contextLimit: 50,
        })
        .expect(201);
      const body = res.body as {
        available: boolean;
        contextEventCount: number;
      };
      expect(body.available).toBe(true);
      expect(body.contextEventCount).toBeGreaterThan(0);

      // The hard assertion: inspect exactly what was sent over the wire to
      // manar-ai, not just that the endpoint "worked".
      expect(fakeServer.lastInvestigateAuditRequest).toBeDefined();
      const sentContext =
        fakeServer.lastInvestigateAuditRequest!.retrievedContext.join('\n');
      expect(sentContext).toContain(taskA.id);
      expect(sentContext).not.toContain(taskB.id);
    } finally {
      await alt.app.close();
      await fakeServer.stop();
    }
  }, 30_000);

  // ---------------------------------------------------------------------
  // 6. POST /incidents/summarize: auditEventIds are resolved only against
  // the caller's own tenant database, and a real advisory is returned when
  // manar-ai is available.
  // ---------------------------------------------------------------------
  it("6. POST /incidents/summarize only resolves auditEventIds belonging to the caller's own tenant", async () => {
    const fakeServer = new FakeAnalysisServiceServer();
    const target = await fakeServer.start();
    fakeServer.incidentSummaryResult = {
      summary: 'A task was created.',
      keyEvents: ['task.created'],
      probableRootCause: 'Routine operation.',
      recommendedNextSteps: [],
      confidence: 0.8,
      explanation: 'test',
    };

    const alt = await bootAltHumanApp(
      buildAiAdvisoryClient({ grpcTarget: target }),
    );
    try {
      const agentA = await createAgent(tokenA, 'summarize-a');
      const taskA = await createTask(tokenA, agentA.id);
      const agentB = await createAgent(tokenB, 'summarize-b');
      const taskB = await createTask(tokenB, agentB.id);

      const tenantClientA = await tenantDatabaseManager.getClient(tenantA.id);
      const tenantClientB = await tenantDatabaseManager.getClient(tenantB.id);
      const eventsA = await tenantClientA.auditEvent.findMany({
        where: { eventType: 'task.created' },
        orderBy: { sequence: 'desc' },
        take: 20,
      });
      const eventA = eventsA.find(
        (e) => (e.data as { taskId?: string }).taskId === taskA.id,
      );
      const eventsB = await tenantClientB.auditEvent.findMany({
        where: { eventType: 'task.created' },
        orderBy: { sequence: 'desc' },
        take: 20,
      });
      const eventB = eventsB.find(
        (e) => (e.data as { taskId?: string }).taskId === taskB.id,
      );
      expect(eventA).toBeDefined();
      expect(eventB).toBeDefined();

      // Tenant A's own real eventId, plus tenant B's real eventId -- the
      // latter simply doesn't exist in tenant A's own database.
      const res = await request(alt.app.getHttpServer() as App)
        .post('/incidents/summarize')
        .set('Authorization', `Bearer ${tokenA}`)
        .send({
          description: 'investigating recent task creation',
          auditEventIds: [eventA!.id, eventB!.id],
        })
        .expect(201);
      const body = res.body as {
        available: boolean;
        result: { summary: string } | null;
        contextEventCount: number;
      };
      expect(body.available).toBe(true);
      expect(body.result?.summary).toBe('A task was created.');
      // Only eventA resolved -- eventB's id was silently omitted, never
      // fetched (it belongs to a physically separate tenant database).
      expect(body.contextEventCount).toBe(1);
    } finally {
      await alt.app.close();
      await fakeServer.stop();
    }
  }, 30_000);
});
