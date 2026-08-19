import 'dotenv/config';
import * as https from 'node:https';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { getOptionsToken } from '@nestjs/throttler';
import request from 'supertest';
import { App } from 'supertest/types';
import { NativeConnection, Worker } from '@temporalio/worker';
import { FileIdentityStore, ManarAgent } from '@manar/sdk-node';
import type { AgentIdentity } from '@manar/sdk-node';
import { AppModule } from '../src/app.module';
import { AgentMtlsAppModule } from '../src/agent-mtls/agent-mtls-app.module';
import { WorkerAppModule } from '../src/temporal/worker-app.module';
import { WebhookDeliveryActivitiesFactory } from '../src/temporal/activities/webhook-delivery.activities';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import type { AppConfig } from '../src/config/env.validation';
import { setupCors, setupHelmet } from '../src/security/setup-security';
import { verifyWebhookSignature } from '../src/webhooks/webhook-signing';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';
import { HttpFixtureServer } from './support/http-fixture-server';

/**
 * Phase 12a (Application Hardening & Webhooks) — the design spec's
 * "Testing" section, run against real local infra (`pnpm infra:up`):
 * real Postgres, Keycloak, OpenBao, OpenFGA, Temporal, Kafka, and Redis.
 *
 * Reuses `test/kill-switches.e2e-spec.ts`'s established harness shape
 * (real `AppModule`/`AgentMtlsAppModule` instances, real tenant
 * provisioning, real SDK enrollment, an in-process Temporal worker for the
 * one scenario that needs it) — see that file for why each of these
 * patterns looks the way it does.
 *
 * **Rate limiting** uses two *additional* app instances
 * (`altHumanApp`/`altAgentMtlsApp`) with their `@nestjs/throttler` options
 * overridden to a tiny limit (`getOptionsToken()` — the framework's own
 * documented extension point for testing a dynamic module's registered
 * options) rather than the real, deliberately-generous default limits
 * (300/120 requests) — bursting past those in a test would be slow and
 * pointless. This override falls back to `@nestjs/throttler`'s built-in
 * in-memory storage (no `storage` field in the overridden options) rather
 * than the real Redis-backed one — `RedisThrottlerStorageService`'s own
 * correctness (including the exact block/reset semantics) is separately,
 * directly proven against real Redis in
 * `src/rate-limit/redis-throttler-storage.service.spec.ts`; what this file
 * needs to prove is that `TenantThrottlerGuard`/`AgentThrottlerGuard`
 * actually trigger a real 429 and partition correctly by tenant/agent,
 * which is independent of which storage backend answers `increment`.
 *
 * **Webhook delivery retry-to-FAILED** (the full exhaustion of Temporal's
 * real ~5-minute-worst-case retry policy) is proven fast and
 * deterministically with mocked Activities + a time-skipping
 * `TestWorkflowEnvironment` in
 * `src/temporal/workflows/webhook-delivery.workflow.spec.ts` instead of
 * here — this file proves a real signed delivery to a real receiver
 * (including a receiver that fails its first two attempts before
 * succeeding, proving the *real* retry path actually fires against real
 * infra, not just the workflow's own decision logic).
 */
describe('App Hardening & Webhooks (e2e)', () => {
  let humanApp: NestFastifyApplication;
  let agentMtlsApp: NestFastifyApplication;
  let altHumanApp: NestFastifyApplication;
  let altAgentMtlsApp: NestFastifyApplication;
  let humanEndpoint: string;
  let agentMtlsEndpoint: string;
  let agentMtlsPort: number;
  let altAgentMtlsPort: number;
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
  let tenant2: ProvisionedTenant;
  let adminToken2: string;

  const ADMIN_USERNAME = `hw-admin-${randomUUID().slice(0, 8)}`;
  const ADMIN_USERNAME_2 = `hw-admin2-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function shortSlug(label: string): string {
    return `hw-${label}-${randomUUID().slice(0, 8)}`;
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
    username: string,
  ): Promise<{ tenant: ProvisionedTenant; token: string }> {
    const provisioned = await provisioning.provisionTenant({
      slug: shortSlug(slugLabel),
      name: `App Hardening Test Tenant ${slugLabel}`,
    });
    if (!provisioned.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }
    const clientSecretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: provisioned.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    const userId = await createRealmUser(provisioned.keycloakRealm, {
      username,
      email: `${username}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(provisioned.keycloakRealm, userId, 'SECURITY_ADMIN');
    const token = await getUserToken({
      realm: provisioned.keycloakRealm,
      clientId: provisioned.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username,
      password: USER_PASSWORD,
    });
    return { tenant: provisioned, token };
  }

  /** Same pattern `test/kill-switches.e2e-spec.ts`'s identical helper uses. */
  async function createEnrolledAgent(
    slugLabel: string,
    token: string = adminToken,
  ): Promise<{
    agentId: string;
    slug: string;
    identity: AgentIdentity;
    manar: ManarAgent;
  }> {
    const slug = shortSlug(slugLabel);
    const createResponse = await request(humanApp.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${token}`)
      .send({ slug, displayName: `Test agent ${slug}` })
      .expect(201);
    const agentId = (createResponse.body as { id: string }).id;

    const tokenResponse = await request(humanApp.getHttpServer() as App)
      .post(`/agents/${agentId}/enrollment-tokens`)
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

    return { agentId, slug, identity, manar };
  }

  interface RawResponse {
    status: number;
    body: unknown;
  }

  /** Raw mTLS request against a specific listener port -- mirrors `test/approvals.e2e-spec.ts`'s identical `mtlsRequest` helper (supertest has no client-certificate support, so every mTLS call in this codebase's e2e suites goes through Node's own `https.request` directly). */
  function mtlsRequest(
    port: number,
    identity: Pick<AgentIdentity, 'certificatePem' | 'privateKeyPem'>,
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
  ): Promise<RawResponse> {
    const bodyText = body !== undefined ? JSON.stringify(body) : undefined;
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: '127.0.0.1',
          port,
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

  interface WebhookCreatedBody {
    id: string;
    url: string;
    subscribedEventTypes: string[];
    enabled: boolean;
    secret: string;
  }

  async function registerWebhook(
    token: string,
    input: {
      url: string;
      subscribedEventTypes: string[];
      idempotencyKey?: string;
    },
  ): Promise<{ status: number; body: WebhookCreatedBody }> {
    const req = request(humanApp.getHttpServer())
      .post('/webhooks')
      .set('Authorization', `Bearer ${token}`);
    if (input.idempotencyKey) {
      req.set('Idempotency-Key', input.idempotencyKey);
    }
    const res = await req.send({
      url: input.url,
      subscribedEventTypes: input.subscribedEventTypes,
    });
    return { status: res.status, body: res.body as WebhookCreatedBody };
  }

  async function waitFor(
    predicate: () => boolean | Promise<boolean>,
    timeoutMs: number,
    intervalMs = 200,
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await predicate()) return;
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    if (!(await predicate())) {
      throw new Error(`waitFor: condition not met within ${timeoutMs}ms`);
    }
  }

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    }).compile();
    humanApp = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await humanApp.init();
    // Phase 12a: security headers + CORS -- real boot code (src/main.ts)
    // calls these explicitly, before the Fastify instance is ready (a
    // Fastify plugin can never be registered after `.ready()`), and this
    // suite's own harness (mirroring every other e2e file's own beforeAll)
    // never boots through main.ts itself, so they're applied here the same
    // way, at the same point in the lifecycle, to actually exercise them
    // against real HTTP responses.
    setupHelmet(humanApp);
    setupCors(humanApp, {
      get: (key: string) =>
        key === 'CORS_ALLOWED_ORIGINS'
          ? 'https://allowed.example.com'
          : humanApp.get(ConfigService<AppConfig, true>).get(key as never, {
              infer: true,
            }),
    } as unknown as ConfigService<AppConfig, true>);
    await humanApp.getHttpAdapter().getInstance().ready();
    await humanApp.listen(0, '127.0.0.1');
    const humanAddress = humanApp.getHttpServer().address() as AddressInfo;
    humanEndpoint = `http://127.0.0.1:${humanAddress.port}`;

    const intermediateCaPath =
      process.env.AGENT_MTLS_CLIENT_CA_PATH ?? 'deploy/openbao/ca-chain.pem';
    fullCaChainPem = readFileSync(intermediateCaPath, 'utf8');

    const mtlsHttpsOptions = {
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
    };

    const agentMtlsFixture: TestingModule = await Test.createTestingModule({
      imports: [AgentMtlsAppModule],
    }).compile();
    agentMtlsApp =
      agentMtlsFixture.createNestApplication<NestFastifyApplication>(
        new FastifyAdapter({ https: mtlsHttpsOptions }),
      );
    await agentMtlsApp.init();
    setupHelmet(agentMtlsApp);
    await agentMtlsApp.getHttpAdapter().getInstance().ready();
    await agentMtlsApp.listen(0, '127.0.0.1');
    const mtlsAddress = agentMtlsApp.getHttpServer().address() as AddressInfo;
    agentMtlsPort = mtlsAddress.port;
    agentMtlsEndpoint = `https://127.0.0.1:${agentMtlsPort}`;

    control = humanApp.get(ControlPrismaService);
    tenantDatabaseManager = humanApp.get(TenantDatabaseManager);
    provisioning = moduleFixture.get(TenantProvisioningService);

    // Rate-limit-scoped alt instances -- see class doc comment.
    const altHumanFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    })
      .overrideProvider(getOptionsToken())
      .useValue({ throttlers: [{ name: 'human', ttl: 30_000, limit: 3 }] })
      .compile();
    altHumanApp = altHumanFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await altHumanApp.init();
    await altHumanApp.getHttpAdapter().getInstance().ready();
    await altHumanApp.listen(0, '127.0.0.1');

    const altAgentMtlsFixture: TestingModule = await Test.createTestingModule({
      imports: [AgentMtlsAppModule],
    })
      .overrideProvider(getOptionsToken())
      .useValue({ throttlers: [{ name: 'agent', ttl: 30_000, limit: 3 }] })
      .compile();
    altAgentMtlsApp =
      altAgentMtlsFixture.createNestApplication<NestFastifyApplication>(
        new FastifyAdapter({ https: mtlsHttpsOptions }),
      );
    await altAgentMtlsApp.init();
    await altAgentMtlsApp.getHttpAdapter().getInstance().ready();
    await altAgentMtlsApp.listen(0, '127.0.0.1');
    altAgentMtlsPort = (
      altAgentMtlsApp.getHttpServer().address() as AddressInfo
    ).port;

    // Real Temporal worker, in-process, on the shared default task queue --
    // matches test/kill-switches.e2e-spec.ts's identical setup (this
    // suite's WebhookDeliveryConsumerService, running inside the real
    // `humanApp`, starts WebhookDeliveryWorkflow executions on its own
    // dedicated `WEBHOOK_DELIVERY_TASK_QUEUE` (deliberately NOT the shared
    // default `manar-approvals` queue -- see that config field's own doc
    // comment, src/webhooks/webhooks.config.ts, for why: several *other*
    // e2e files' own in-process workers narrowly bundle only
    // approval.workflow.ts and would crash if a WebhookDeliveryWorkflow
    // task ever landed on the queue they're polling), so this worker polls
    // that same dedicated queue to pick them up.
    workerModuleFixture = await Test.createTestingModule({
      imports: [WorkerAppModule],
    }).compile();
    const activities = workerModuleFixture
      .get(WebhookDeliveryActivitiesFactory)
      .build();
    const temporalAddress = process.env.TEMPORAL_ADDRESS ?? 'localhost:7233';
    temporalConnection = await NativeConnection.connect({
      address: temporalAddress,
    });
    temporalWorker = await Worker.create({
      connection: temporalConnection,
      namespace: process.env.TEMPORAL_NAMESPACE ?? 'default',
      taskQueue: process.env.WEBHOOK_DELIVERY_TASK_QUEUE ?? 'manar-webhooks',
      workflowsPath: join(process.cwd(), 'src/temporal/workflows/index.ts'),
      activities,
    });
    temporalWorkerRunPromise = temporalWorker.run();

    const first = await provisionTestTenant('t1', ADMIN_USERNAME);
    tenant = first.tenant;
    adminToken = first.token;

    const second = await provisionTestTenant('t2', ADMIN_USERNAME_2);
    tenant2 = second.tenant;
    adminToken2 = second.token;
  }, 240_000);

  afterAll(async () => {
    temporalWorker?.shutdown();
    await temporalWorkerRunPromise;
    await temporalConnection?.close();
    await workerModuleFixture?.close();

    await humanApp.close();
    await agentMtlsApp.close();
    await altHumanApp.close();
    await altAgentMtlsApp.close();
    if (tenant) await cleanupTenant(tenant);
    if (tenant2) await cleanupTenant(tenant2);
  }, 120_000);

  // ---------------------------------------------------------------------
  // Security headers & CORS.
  // ---------------------------------------------------------------------

  describe('security headers & CORS', () => {
    it('helmet security headers are present on a real human-app response', async () => {
      const res = await request(humanApp.getHttpServer() as App)
        .get('/health/live')
        .expect(200);
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBeDefined();
    });

    it('helmet security headers are present on a real mTLS agent-app response', async () => {
      const { identity } = await createEnrolledAgent('hdr');
      const res = await new Promise<{
        status: number;
        headers: Record<string, string | string[] | undefined>;
      }>((resolve, reject) => {
        const req = https.request(
          {
            host: '127.0.0.1',
            port: agentMtlsPort,
            path: '/agent/v1/whoami',
            method: 'GET',
            cert: identity.certificatePem,
            key: identity.privateKeyPem,
            ca: fullCaChainPem,
            rejectUnauthorized: true,
          },
          (r) => {
            r.on('data', () => undefined);
            r.on('end', () =>
              resolve({ status: r.statusCode ?? 0, headers: r.headers }),
            );
          },
        );
        req.on('error', reject);
        req.end();
      });
      expect(res.status).toBe(200);
      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    it('CORS reflects an allow-listed origin', async () => {
      const res = await request(humanApp.getHttpServer() as App)
        .get('/health/live')
        .set('Origin', 'https://allowed.example.com')
        .expect(200);
      expect(res.headers['access-control-allow-origin']).toBe(
        'https://allowed.example.com',
      );
    });

    it('CORS does NOT reflect a non-allow-listed origin (no Access-Control-Allow-Origin header at all)', async () => {
      const res = await request(humanApp.getHttpServer() as App)
        .get('/health/live')
        .set('Origin', 'https://not-allowed.example.com')
        .expect(200);
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------
  // Rate limiting.
  // ---------------------------------------------------------------------

  describe('rate limiting', () => {
    it('a burst past the configured limit on the human surface gets throttled (429)', async () => {
      const statuses: number[] = [];
      for (let i = 0; i < 5; i += 1) {
        const res = await request(altHumanApp.getHttpServer())
          .get('/webhooks')
          .set('Authorization', `Bearer ${adminToken}`);
        statuses.push(res.status);
      }
      expect(statuses.slice(0, 3).every((s) => s === 200)).toBe(true);
      expect(statuses.slice(3)).toContain(429);
    });

    it("tenant A's burst does not exhaust tenant B's own limit (per-tenant scoping)", async () => {
      // Exhaust tenant A's bucket on the alt app.
      for (let i = 0; i < 4; i += 1) {
        await request(altHumanApp.getHttpServer())
          .get('/webhooks')
          .set('Authorization', `Bearer ${adminToken}`);
      }
      // Tenant B, same alt app, same route -- unaffected.
      const res = await request(altHumanApp.getHttpServer())
        .get('/webhooks')
        .set('Authorization', `Bearer ${adminToken2}`);
      expect(res.status).toBe(200);
    });

    it('a burst past the configured limit on the mTLS agent surface gets throttled (429)', async () => {
      const { identity } = await createEnrolledAgent('rl-a');
      const statuses: number[] = [];
      for (let i = 0; i < 5; i += 1) {
        const res = await mtlsRequest(
          altAgentMtlsPort,
          identity,
          'GET',
          '/agent/v1/whoami',
        );
        statuses.push(res.status);
      }
      expect(statuses.slice(0, 3).every((s) => s === 200)).toBe(true);
      expect(statuses.slice(3)).toContain(429);
    });

    it("a different agent's requests are not blocked by another agent's exhausted limit (per-agent scoping)", async () => {
      const agentA = await createEnrolledAgent('rl-b1');
      const agentB = await createEnrolledAgent('rl-b2');

      for (let i = 0; i < 4; i += 1) {
        await mtlsRequest(
          altAgentMtlsPort,
          agentA.identity,
          'GET',
          '/agent/v1/whoami',
        );
      }
      const res = await mtlsRequest(
        altAgentMtlsPort,
        agentB.identity,
        'GET',
        '/agent/v1/whoami',
      );
      expect(res.status).toBe(200);
    });
  });

  // ---------------------------------------------------------------------
  // SSRF protection (webhook registration + call-time re-validation).
  // ---------------------------------------------------------------------

  describe('SSRF protection', () => {
    it.each([
      // Note: NOT 127.0.0.1 itself -- SSRF_ALLOWED_HOSTS (.env) explicitly
      // allow-lists that exact hostname so this file's own webhook-delivery
      // tests below (which necessarily use HttpFixtureServer, bound to
      // 127.0.0.1) keep working -- see ssrf.config.ts's doc comment for why
      // that operator-controlled exception exists. 127.0.0.2 is still
      // loopback (127.0.0.0/8) and is deliberately NOT on that allow-list,
      // so it proves the general loopback rejection still holds.
      ['loopback', 'http://127.0.0.2:9999/hook'],
      [
        'link-local metadata service',
        'http://169.254.169.254/latest/meta-data/',
      ],
      ['private RFC1918', 'http://10.1.2.3/hook'],
    ])('rejects webhook registration with a %s URL', async (_label, url) => {
      const res = await registerWebhook(adminToken, {
        url,
        subscribedEventTypes: ['agent.enrolled'],
      });
      expect(res.status).toBe(400);
    });

    it('a webhook registered with a normal URL, later re-pointed at a private address, is blocked at DELIVERY (call) time -- never reaches SUCCESS', async () => {
      const receiver = new HttpFixtureServer();
      const publicLookingUrl = await receiver.start(); // a real, reachable 127.0.0.1 fixture -- passes registration
      const created = await registerWebhook(adminToken, {
        url: publicLookingUrl,
        subscribedEventTypes: ['agent.enrolled'],
      });
      expect(created.status).toBe(201);

      // Simulate a URL that now resolves internally (standing in for DNS
      // rebinding -- the unit-level DNS-rebinding proof already covers the
      // resolver-level mechanism deterministically; this proves the real
      // delivery path actually re-checks at call time, end to end) by
      // reconfiguring the endpoint directly to a private address.
      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      await tenantClient.webhookEndpoint.update({
        where: { id: created.body.id },
        data: { url: 'http://169.254.169.254/latest/meta-data/' },
      });

      await createEnrolledAgent('ssrf');

      // Give the consumer + at least one delivery attempt a moment, then
      // confirm it was never actually reached (no request recorded) and
      // never reports SUCCESS.
      await new Promise((resolve) => setTimeout(resolve, 8_000));
      expect(receiver.requests.length).toBe(0);
      const delivery = await tenantClient.webhookDelivery.findFirst({
        where: { webhookEndpointId: created.body.id },
      });
      expect(delivery).not.toBeNull();
      expect(delivery?.status).not.toBe('SUCCESS');
      expect(delivery?.responseStatus).toBeNull();

      await receiver.stop();
    }, 30_000);
  });

  // ---------------------------------------------------------------------
  // Webhooks: real signed delivery, signature verification, real retry.
  // ---------------------------------------------------------------------

  describe('webhook delivery', () => {
    it('a subscribed event triggers a real signed delivery whose signature verifies', async () => {
      const receiver = new HttpFixtureServer();
      const url = await receiver.start();
      const created = await registerWebhook(adminToken, {
        url,
        subscribedEventTypes: ['agent.enrolled'],
      });
      expect(created.status).toBe(201);

      await createEnrolledAgent('sign');

      await waitFor(() => receiver.requests.length > 0, 20_000);
      const received = receiver.requests[0]!;
      expect(received.headers['manar-event-type']).toBe('agent.enrolled');
      expect(received.headers['manar-delivery-id']).toBeDefined();

      const signature = received.headers['manar-signature'] as string;
      const timestamp = received.headers['manar-timestamp'] as string;
      const valid = verifyWebhookSignature(
        created.body.secret,
        received.rawBody,
        signature,
        timestamp,
        5 * 60 * 1000,
      );
      expect(valid).toBe(true);

      // A wrong secret must NOT verify -- proves this isn't a tautology.
      const invalid = verifyWebhookSignature(
        'definitely-the-wrong-secret',
        received.rawBody,
        signature,
        timestamp,
        5 * 60 * 1000,
      );
      expect(invalid).toBe(false);

      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      await waitFor(async () => {
        const delivery = await tenantClient.webhookDelivery.findFirst({
          where: { webhookEndpointId: created.body.id },
        });
        return delivery?.status === 'SUCCESS';
      }, 15_000);

      await receiver.stop();
    }, 40_000);

    it('an endpoint that fails its first two attempts and then succeeds is delivered via a REAL retry (not just first-try success)', async () => {
      const receiver = new HttpFixtureServer();
      let attempts = 0;
      const url = await receiver.start();
      receiver.setResponse(() => {
        attempts += 1;
        return attempts <= 2
          ? { status: 500, body: { error: 'try again' } }
          : { status: 200, body: { ok: true } };
      });

      const created = await registerWebhook(adminToken, {
        url,
        subscribedEventTypes: ['agent.revoked'],
      });
      expect(created.status).toBe(201);

      const { agentId } = await createEnrolledAgent('retry');
      await request(humanApp.getHttpServer() as App)
        .post(`/agents/${agentId}/revoke`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'app-hardening e2e retry test' })
        .expect(201);

      const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
      // The workflow's real retry policy backs off 5s then 10s between
      // attempts -- allow enough real wall-clock time for both retries to
      // actually happen.
      await waitFor(async () => {
        const delivery = await tenantClient.webhookDelivery.findFirst({
          where: { webhookEndpointId: created.body.id },
        });
        return delivery?.status === 'SUCCESS';
      }, 40_000);

      const delivery = await tenantClient.webhookDelivery.findFirst({
        where: { webhookEndpointId: created.body.id },
      });
      expect(delivery?.attempts).toBeGreaterThanOrEqual(3);
      expect(delivery?.responseStatus).toBe(200);
      expect(receiver.requests.length).toBeGreaterThanOrEqual(3);

      await receiver.stop();
    }, 60_000);
  });

  // ---------------------------------------------------------------------
  // Idempotency-Key.
  // ---------------------------------------------------------------------

  describe('idempotency', () => {
    it('replaying a webhook registration with the SAME Idempotency-Key does not create a second WebhookEndpoint', async () => {
      const key = `idem-${randomUUID()}`;
      const url = 'http://127.0.0.1:9/does-not-matter';
      const first = await registerWebhook(adminToken2, {
        url,
        subscribedEventTypes: ['agent.enrolled'],
        idempotencyKey: key,
      });
      expect(first.status).toBe(201);

      const second = await registerWebhook(adminToken2, {
        url,
        subscribedEventTypes: ['agent.enrolled'],
        idempotencyKey: key,
      });
      expect(second.status).toBe(201);
      // Same id AND same secret -- proves the second call never actually
      // re-ran WebhookRegistryService.create (which would have generated
      // and stored a brand-new secret).
      expect(second.body.id).toBe(first.body.id);
      expect(second.body.secret).toBe(first.body.secret);

      const tenantClient = await tenantDatabaseManager.getClient(tenant2.id);
      const count = await tenantClient.webhookEndpoint.count({
        where: { id: first.body.id },
      });
      expect(count).toBe(1);
    });

    it('a DIFFERENT Idempotency-Key creates a genuinely new WebhookEndpoint', async () => {
      const url = 'http://127.0.0.1:9/does-not-matter';
      const first = await registerWebhook(adminToken2, {
        url,
        subscribedEventTypes: ['agent.enrolled'],
        idempotencyKey: `idem-${randomUUID()}`,
      });
      const second = await registerWebhook(adminToken2, {
        url,
        subscribedEventTypes: ['agent.enrolled'],
        idempotencyKey: `idem-${randomUUID()}`,
      });
      expect(first.body.id).not.toBe(second.body.id);
      expect(first.body.secret).not.toBe(second.body.secret);
    });
  });
});
