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
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';

/**
 * Phase 15a (Section 55) mandatory scenario: "Compliance endpoints return
 * the real seeded mappings; assert the API response never contains
 * certification language." Mirrors `test/tenant-settings.e2e-spec.ts`'s
 * simpler (no mTLS agent listener needed) boilerplate.
 */
describe('Compliance mapping (e2e)', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let provisioning: TenantProvisioningService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let userToken: string;

  const USERNAME = `compliance-user-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `compl-${label}-${randomUUID().slice(0, 8)}`;
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
    provisioning = app.get(TenantProvisioningService);

    tenant = await provisioning.provisionTenant({
      slug: uniqueSlug('t'),
      name: 'Compliance Mapping Test Tenant',
    });
    if (!tenant.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }

    const secretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });

    const userId = await createRealmUser(tenant.keycloakRealm, {
      username: USERNAME,
      email: `${USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    // Only the least role -- ComplianceController is JWT-guarded only
    // (Section 55: reference content, not sensitive per-tenant data,
    // mirrors GET /users's posture), so any member must succeed. A
    // Membership always holds a role; READ_ONLY is the least.
    await assignRealmRole(tenant.keycloakRealm, userId, 'READ_ONLY');

    userToken = await getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: secretRef.reference,
      username: USERNAME,
      password: USER_PASSWORD,
    });
  }, 120_000);

  afterAll(async () => {
    await app.close();
    if (tenant) await cleanupTenant(tenant);
    await control.$disconnect();
  }, 60_000);

  it('GET /compliance/frameworks returns the two real seeded frameworks (ISO/IEC 27001:2022, NIST AI RMF 1.0)', async () => {
    const response = await request(app.getHttpServer() as App)
      .get('/compliance/frameworks')
      .set('Authorization', `Bearer ${userToken}`)
      .expect(200);

    const body = response.body as {
      items: Array<{ id: string; name: string; version: string }>;
    };
    expect(body.items).toHaveLength(2);
    const byName = Object.fromEntries(
      body.items.map((f) => [f.name, f.version]),
    );
    expect(byName['ISO/IEC 27001']).toBe('2022');
    expect(byName['NIST AI RMF']).toBe('1.0 (NIST.AI.100-1)');
  });

  it('GET /compliance/frameworks/:id/controls returns the real seeded controls with real mapping statuses, and the response never contains certification language', async () => {
    const frameworksResponse = await request(app.getHttpServer() as App)
      .get('/compliance/frameworks')
      .set('Authorization', `Bearer ${userToken}`)
      .expect(200);
    const frameworks = (
      frameworksResponse.body as {
        items: Array<{ id: string; name: string }>;
      }
    ).items;
    const iso = frameworks.find((f) => f.name === 'ISO/IEC 27001');
    expect(iso).toBeDefined();

    const controlsResponse = await request(app.getHttpServer() as App)
      .get(`/compliance/frameworks/${iso!.id}/controls`)
      .set('Authorization', `Bearer ${userToken}`)
      .expect(200);

    const body = controlsResponse.body as {
      items: Array<{
        controlId: string;
        title: string;
        description: string;
        mapping: {
          status: string;
          evidenceDescription: string;
          evidenceReference: string | null;
          assessedAt: string;
        } | null;
      }>;
    };

    expect(body.items.length).toBeGreaterThan(0);
    const accessControl = body.items.find((c) => c.controlId === 'A.5.15');
    expect(accessControl).toBeDefined();
    expect(accessControl!.title).toBe('Access control');
    expect(accessControl!.mapping).not.toBeNull();
    expect(accessControl!.mapping!.status).toBe('MAPPED');
    expect(accessControl!.mapping!.evidenceDescription).toContain(
      'docs/authorization-model.md',
    );

    const validStatuses = new Set([
      'MAPPED',
      'EVIDENCE_AVAILABLE',
      'PARTIALLY_IMPLEMENTED',
      'NOT_EVALUATED',
    ]);
    for (const control of body.items) {
      expect(control.mapping).not.toBeNull();
      expect(validStatuses.has(control.mapping!.status)).toBe(true);
    }

    // Section 55's non-negotiable constraint: never claim certification.
    const rawResponseText = JSON.stringify(controlsResponse.body);
    expect(rawResponseText.toLowerCase()).not.toContain('certified');
    expect(rawResponseText.toLowerCase()).not.toContain('certification');
  });

  it('GET /compliance/frameworks/:id/controls 404s for an unknown framework id', async () => {
    await request(app.getHttpServer() as App)
      .get(`/compliance/frameworks/${randomUUID()}/controls`)
      .set('Authorization', `Bearer ${userToken}`)
      .expect(404);
  });

  it('requires authentication', async () => {
    await request(app.getHttpServer() as App)
      .get('/compliance/frameworks')
      .expect(401);
  });
});
