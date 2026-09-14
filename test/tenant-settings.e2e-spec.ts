import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import type { ConfigService } from '@nestjs/config';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import type { AppConfig } from '../src/config/env.validation';
import { AiAdvisoryClient } from '../src/ai-advisory/ai-advisory-client.service';
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
import { FakeAnalysisServiceServer } from './support/fake-analysis-service-server';

/**
 * Phase 14 (Users/Roles/Settings) — `GET`/`PATCH /tenant/settings`, run
 * against real local infra (`pnpm infra:up`): real Postgres, real
 * Keycloak, exactly like `test/auth.e2e-spec.ts`.
 *
 * The mandatory scenario from this phase's design spec is scenario 5
 * below: confirming `allowExternalAi = false` (set via this endpoint) is
 * effective on the *very next* AI-advisory-eligible request, not just
 * eventually — proven against a real `AiAdvisoryClient` pointed at a real
 * gRPC server (`FakeAnalysisServiceServer`, same tool
 * `test/ai-advisory.e2e-spec.ts` uses), asserting the RPC either does or
 * does not reach that server, not just inspecting the `Tenant` row.
 */
describe('Tenant Settings (e2e)', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let clientSecret: string;
  let ownerToken: string;
  let plainToken: string;

  const OWNER_USERNAME = `tsowner-${randomUUID().slice(0, 8)}`;
  const PLAIN_USERNAME = `tsplain-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `tsettings-${label}-${randomUUID().slice(0, 8)}`;
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
   * A real `AiAdvisoryClient`, constructed directly (not through DI) —
   * same pattern `test/ai-advisory.e2e-spec.ts`'s own `buildAiAdvisoryClient`
   * helper uses, extended here with an explicit `provider` override so this
   * file can exercise the `allowExternalAi` residency gate (Phase 12a,
   * Section 54), which that file's own helper deliberately never varies
   * (see its doc comment).
   */
  function buildAiAdvisoryClient(overrides: {
    grpcTarget: string;
    provider: 'anthropic' | 'ollama' | 'vllm';
  }): AiAdvisoryClient {
    const values = {
      AI_ADVISORY_GRPC_TARGET: overrides.grpcTarget,
      AI_ADVISORY_TIMEOUT_MS: 2000,
      AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 3,
      AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
      AI_ADVISORY_LONGFORM_TIMEOUT_MS: 30_000,
      AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD: 3,
      AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
      AI_ADVISORY_PROVIDER: overrides.provider,
      // Release 2026-11-11: mTLS to manar-ai is off by default; the
      // developer stack still uses manar-ai's plaintext listener.
      AI_ADVISORY_TLS_ENABLED: 'false',
    };
    const configService = {
      get: (key: string) => (values as Record<string, unknown>)[key],
    } as unknown as ConfigService<AppConfig, true>;
    return new AiAdvisoryClient(configService, control);
  }

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule, KeycloakModule],
    }).compile();

    app = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    control = app.get(ControlPrismaService);
    tenantDatabaseManager = app.get(TenantDatabaseManager);
    provisioning = app.get(TenantProvisioningService);

    tenant = await provisioning.provisionTenant({
      slug: uniqueSlug('t'),
      name: 'Tenant Settings Test Tenant',
    });
    if (!tenant.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }

    const secretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    clientSecret = secretRef.reference;

    const ownerId = await createRealmUser(tenant.keycloakRealm, {
      username: OWNER_USERNAME,
      email: `${OWNER_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm, ownerId, 'TENANT_OWNER');

    await createRealmUser(tenant.keycloakRealm, {
      username: PLAIN_USERNAME,
      email: `${PLAIN_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });

    ownerToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret,
      username: OWNER_USERNAME,
      password: USER_PASSWORD,
    });
    plainToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret,
      username: PLAIN_USERNAME,
      password: USER_PASSWORD,
    });
  }, 120_000);

  afterAll(async () => {
    await app.close();
    if (tenant) await cleanupTenant(tenant);
    await control.$disconnect();
  }, 60_000);

  it('1. GET /tenant/settings surfaces the real Tenant row plus read-only SSO/AI-provider/rate-limit info', async () => {
    const response = await request(app.getHttpServer() as App)
      .get('/tenant/settings')
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(200);

    const body = response.body as {
      tenantId: string;
      slug: string;
      residency: string;
      allowExternalAi: boolean;
      allowOutboundTelemetry: boolean;
      allowCloudStorage: boolean;
      sso: { realm: string; issuerUrl: string } | null;
      aiProvider: { provider: string; isExternal: boolean };
      rateLimit: { humanRequestLimit: number; humanWindowMs: number };
    };

    expect(body.tenantId).toBe(tenant.id);
    expect(body.slug).toBe(tenant.slug);
    // Phase 2 defaults.
    expect(body.residency).toBe('UAE');
    expect(body.allowExternalAi).toBe(false);
    expect(body.allowOutboundTelemetry).toBe(false);
    expect(body.allowCloudStorage).toBe(false);

    expect(body.sso).not.toBeNull();
    expect(body.sso!.realm).toBe(tenant.keycloakRealm);
    expect(body.sso!.issuerUrl).toBe(tenant.keycloakIssuerUrl);

    const expectedProvider = process.env.AI_ADVISORY_PROVIDER ?? 'ollama';
    expect(body.aiProvider.provider).toBe(expectedProvider);
    expect(body.aiProvider.isExternal).toBe(expectedProvider === 'anthropic');

    expect(body.rateLimit.humanRequestLimit).toBe(
      Number(process.env.RATE_LIMIT_HUMAN_LIMIT ?? 300),
    );
    expect(body.rateLimit.humanWindowMs).toBe(
      Number(process.env.RATE_LIMIT_HUMAN_TTL_MS ?? 60_000),
    );
  });

  it('2. only TENANT_OWNER/SECURITY_ADMIN may read or write tenant settings', async () => {
    await request(app.getHttpServer() as App)
      .get('/tenant/settings')
      .set('Authorization', `Bearer ${plainToken}`)
      .expect(403);

    await request(app.getHttpServer() as App)
      .patch('/tenant/settings')
      .set('Authorization', `Bearer ${plainToken}`)
      .send({ allowCloudStorage: true })
      .expect(403);
  });

  it('3. PATCH persists a partial update and rejects an empty body', async () => {
    await request(app.getHttpServer() as App)
      .patch('/tenant/settings')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({})
      .expect(400);

    const patchResponse = await request(app.getHttpServer() as App)
      .patch('/tenant/settings')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ allowCloudStorage: true, residency: 'CUSTOM_REGION' })
      .expect(200);
    const patchBody = patchResponse.body as {
      allowCloudStorage: boolean;
      residency: string;
      allowExternalAi: boolean;
    };
    expect(patchBody.allowCloudStorage).toBe(true);
    expect(patchBody.residency).toBe('CUSTOM_REGION');
    // Untouched field is unchanged.
    expect(patchBody.allowExternalAi).toBe(false);

    // Persists across a fresh GET, not just echoed back in the PATCH response.
    const getResponse = await request(app.getHttpServer() as App)
      .get('/tenant/settings')
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(200);
    const getBody = getResponse.body as {
      allowCloudStorage: boolean;
      residency: string;
    };
    expect(getBody.allowCloudStorage).toBe(true);
    expect(getBody.residency).toBe('CUSTOM_REGION');
  });

  it('4. PATCH /tenant/settings is audited', async () => {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const events = await tenantClient.auditEvent.findMany({
      where: { eventType: 'tenant.settings_updated' },
    });
    expect(events.length).toBeGreaterThan(0);
  });

  it('5. toggling allowExternalAi takes effect on the very next AI-advisory-eligible request -- verified against a real gRPC call, not assumed', async () => {
    const fakeServer = new FakeAnalysisServiceServer();
    const target = await fakeServer.start();
    try {
      const client = buildAiAdvisoryClient({
        grpcTarget: target,
        provider: 'anthropic', // the one provider AiAdvisoryClient treats as "external"
      });

      // Start from allowExternalAi = true via the real endpoint under test.
      await request(app.getHttpServer() as App)
        .patch('/tenant/settings')
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ allowExternalAi: true })
        .expect(200);

      fakeServer.riskResult = {
        score: 42,
        confidence: 0.9,
        signals: ['test-signal'],
        explanation: 'residency currently allows this',
        recommendedAction: 0,
      };
      const allowedResult = await client.analyzeRisk({
        actionDescription: 'test action',
        context: 'test context',
        tenantId: tenant.id,
      });
      expect(allowedResult).not.toBeNull();
      expect(fakeServer.callCounts.analyzeRisk).toBe(1);

      // Flip it off via the real endpoint -- no restart, no cache-bust,
      // just the next call against the exact same AiAdvisoryClient
      // instance.
      await request(app.getHttpServer() as App)
        .patch('/tenant/settings')
        .set('Authorization', `Bearer ${ownerToken}`)
        .send({ allowExternalAi: false })
        .expect(200);

      const blockedResult = await client.analyzeRisk({
        actionDescription: 'test action',
        context: 'test context',
        tenantId: tenant.id,
      });
      expect(blockedResult).toBeNull();
      // The RPC was never attempted a second time -- residency blocked it
      // before any network call, not merely a response the fake server
      // happened to reject.
      expect(fakeServer.callCounts.analyzeRisk).toBe(1);
    } finally {
      await fakeServer.stop();
    }
  }, 30_000);
});
