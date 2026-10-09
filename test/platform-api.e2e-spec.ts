import {
  PLATFORM_E2E_CLIENT_ID,
  PLATFORM_E2E_ROLE,
  PLATFORM_E2E_SUFFIX,
} from './support/platform-api-env';
import { Client as PgClient } from 'pg';
import { Test } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { randomUUID } from 'node:crypto';
import { ConfigService } from '@nestjs/config';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KillSwitchService } from '../src/kill-switches/kill-switch.service';
import { AuditService } from '../src/audit/audit.service';
import {
  PLATFORM_SWITCH_TARGET,
  PlatformSuspension,
} from '../src/platform/platform-suspension';
import { vi } from 'vitest';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient as TenantPrismaClient } from '../src/generated/tenant-client/client';
import {
  assignRealmRole,
  createPlatformClient,
  createRealmUser,
  deletePlatformClient,
  deleteRealm,
  getClientCredentialsToken,
  getUserToken,
} from './support/keycloak-test-helpers';

/**
 * ADR-0010: the platform API manar-fleet uses for tenant lifecycle, against real Postgres and
 * Keycloak. A client-credentials client in the master realm with a dedicated role is the only
 * accepted caller; suspend cuts the tenant's humans off at once, resume restores them.
 */
interface TenantBody {
  id: string;
  status: string;
  admins?: unknown;
  tools?: unknown;
  agents?: unknown;
}
const body = (r: { body: unknown }) => r.body as TenantBody;

describe('Platform API for manar-fleet (e2e)', () => {
  const suffix = PLATFORM_E2E_SUFFIX;
  const CLIENT_ID = PLATFORM_E2E_CLIENT_ID;
  const NO_ROLE_CLIENT_ID = `manar-fleet-norole-${suffix}`;
  const ROLE = PLATFORM_E2E_ROLE;
  const SLUG = `platform-e2e-${suffix}`;
  const PASSWORD = 'Passw0rd!Test';
  const OWNER = `powner-${suffix}`;

  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let platformClient: { uuid: string; secret: string };
  let noRoleClient: { uuid: string; secret: string };
  let platformToken: string;
  let tenantId: string | undefined;
  let ownerToken: string;
  const http = () => request(app.getHttpServer());

  /** Direct tenant DB access for the test, bypassing the ACTIVE check (the tenant is suspended). */
  async function withTenantClient<T>(
    fn: (db: TenantPrismaClient) => Promise<T>,
  ): Promise<T> {
    const binding = await control.tenantDatabaseBinding.findUniqueOrThrow({
      where: { tenantId },
    });
    const url = new URL(process.env.TENANT_DB_BASE_URL!);
    url.pathname = `/${binding.databaseName}`;
    const db = new TenantPrismaClient({
      adapter: new PrismaPg({ connectionString: url.toString() }),
    });
    try {
      return await fn(db);
    } finally {
      await db.$disconnect();
    }
  }

  beforeAll(async () => {
    platformClient = await createPlatformClient(CLIENT_ID, ROLE);
    noRoleClient = await createPlatformClient(NO_ROLE_CLIENT_ID, null);
    platformToken = await getClientCredentialsToken(
      CLIENT_ID,
      platformClient.secret,
    );

    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    app = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
    control = app.get(ControlPrismaService);
  }, 120_000);

  afterAll(async () => {
    await app?.close();
    await deletePlatformClient(platformClient?.uuid, ROLE);
    await deletePlatformClient(noRoleClient?.uuid);
    if (tenantId) {
      await deleteRealm(SLUG);
      const binding = await control.tenantDatabaseBinding.findUnique({
        where: { tenantId },
      });
      if (binding) {
        const admin = new PgClient({
          connectionString: process.env.CONTROL_DATABASE_URL,
        });
        await admin.connect();
        await admin.query(
          `DROP DATABASE IF EXISTS "${binding.databaseName}" WITH (FORCE)`,
        );
        await admin.end();
      }
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    delete process.env.PLATFORM_API_ISSUER;
    delete process.env.PLATFORM_API_CLIENT_ID;
    delete process.env.PLATFORM_API_ROLE;
  }, 60_000);

  it('rejects calls without a token and without the platform role', async () => {
    await http().get('/platform/v1/tenants').expect(401);
    const noRole = await getClientCredentialsToken(
      NO_ROLE_CLIENT_ID,
      noRoleClient.secret,
    );
    await http()
      .get('/platform/v1/tenants')
      .set('Authorization', `Bearer ${noRole}`)
      .expect(401); // azp is another client
  });

  it('provisions a tenant (database and realm)', async () => {
    const res = await http()
      .post('/platform/v1/tenants')
      .set('Authorization', `Bearer ${platformToken}`)
      .send({ slug: SLUG, name: 'Platform E2E' })
      .expect(201);
    expect(res.body).toMatchObject({
      slug: SLUG,
      status: 'ACTIVE',
      residency: 'UAE',
    });
    tenantId = body(res).id;
    await http()
      .post('/platform/v1/tenants')
      .set('Authorization', `Bearer ${platformToken}`)
      .send({ slug: SLUG, name: 'again' })
      .expect(409);
    await http()
      .post('/platform/v1/tenants')
      .set('Authorization', `Bearer ${platformToken}`)
      .send({ slug: 'Bad Slug', name: 'x' })
      .expect(400);
  }, 120_000);

  it('a tenant user token is never accepted on the platform API', async () => {
    const tenant = await control.tenant.findUniqueOrThrow({
      where: { id: tenantId },
    });
    const secret = await control.secretReference.findFirstOrThrow({
      where: { tenantId, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    const ownerId = await createRealmUser(SLUG, {
      username: OWNER,
      email: `${OWNER}@example.test`,
      password: PASSWORD,
    });
    await assignRealmRole(SLUG, ownerId, 'TENANT_OWNER');
    ownerToken = await getUserToken({
      realm: SLUG,
      clientId: tenant.keycloakClientId!,
      clientSecret: secret.reference,
      username: OWNER,
      password: PASSWORD,
    });
    await http()
      .get('/users')
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(200);
    await http()
      .get('/platform/v1/tenants')
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(401);
  });

  it('lists tenants and summarises one: admins, tools, agents, usage', async () => {
    const list = await http()
      .get('/platform/v1/tenants')
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    expect((list.body as { id: string }[]).map((t) => t.id)).toContain(
      tenantId,
    );
    const res = await http()
      .get(`/platform/v1/tenants/${tenantId}`)
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    expect(body(res).admins).toEqual([
      expect.objectContaining({
        email: `${OWNER}@example.test`,
        roles: ['TENANT_OWNER'],
      }),
    ]);
    expect(res.body).toMatchObject({
      agents: { total: 0, active: 0 },
      usage: { windowDays: 30, tasks: 0 },
    });
    expect(Array.isArray(body(res).tools)).toBe(true);
  });

  it('suspend denies on the decision path in another process at once (kill switch); resume restores it', async () => {
    // A second TenantDatabaseManager stands in for another process (API replica or the worker)
    // that already holds a cached client for this tenant.
    const other = new TenantDatabaseManager(
      control,
      app.get(ConfigService),
      new EnvSecretProvider(),
    );
    const killSwitches = app.get(KillSwitchService);
    const otherClient = await other.getClient(tenantId!);
    const agentId = randomUUID();
    try {
      expect(
        (await killSwitches.checkAll(otherClient, tenantId!, { agentId }))
          .killed,
      ).toBe(false);

      const s = await http()
        .post(`/platform/v1/tenants/${tenantId}/suspend`)
        .set('Authorization', `Bearer ${platformToken}`)
        .expect(200);
      expect(body(s).status).toBe('SUSPENDED');
      // No revalidation wait: the TENANT kill switch is read per decision.
      expect(
        await killSwitches.checkAll(otherClient, tenantId!, { agentId }),
      ).toMatchObject({ killed: true, scope: 'TENANT' });
      await http()
        .get('/users')
        .set('Authorization', `Bearer ${ownerToken}`)
        .expect(401);
      await http()
        .post(`/platform/v1/tenants/${tenantId}/suspend`)
        .set('Authorization', `Bearer ${platformToken}`)
        .expect(409);
      const summary = await http()
        .get(`/platform/v1/tenants/${tenantId}`)
        .set('Authorization', `Bearer ${platformToken}`)
        .expect(200);
      expect(body(summary).status).toBe('SUSPENDED');
      expect(body(summary).agents).toBeUndefined();

      const r = await http()
        .post(`/platform/v1/tenants/${tenantId}/resume`)
        .set('Authorization', `Bearer ${platformToken}`)
        .expect(200);
      expect(body(r).status).toBe('ACTIVE');
      expect(
        (await killSwitches.checkAll(otherClient, tenantId!, { agentId }))
          .killed,
      ).toBe(false);
      await http()
        .get('/users')
        .set('Authorization', `Bearer ${ownerToken}`)
        .expect(200);
    } finally {
      await other.onModuleDestroy();
    }
  });

  it('a human stop pressed during a suspension survives resume', async () => {
    const killSwitches = app.get(KillSwitchService);
    const agentId = randomUUID();
    await http()
      .post(`/platform/v1/tenants/${tenantId}/suspend`)
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    // The console is closed to humans while suspended, so the stop goes in through the service,
    // as the console would write it: the humans' row (targetId null).
    const owner = await withTenantClient((t) =>
      t.userProfile.findFirstOrThrow({
        where: { email: `${OWNER}@example.test` },
      }),
    );
    await withTenantClient((t) =>
      killSwitches.activate(t, tenantId!, {
        scope: 'TENANT',
        targetId: null,
        activatedBy: owner.id,
        reason: 'incident',
      }),
    );
    await http()
      .post(`/platform/v1/tenants/${tenantId}/resume`)
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    const t = await app.get(TenantDatabaseManager).getClient(tenantId!);
    expect(
      await killSwitches.checkAll(t, tenantId!, { agentId }),
    ).toMatchObject({ killed: true, scope: 'TENANT' });
    expect(
      await t.killSwitch.findFirst({
        where: { scope: 'TENANT', targetId: null },
      }),
    ).toMatchObject({ active: true, reason: 'incident' });
    await http()
      .post('/tenants/kill-switch/deactivate')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({})
      .expect(201);
    expect(
      (await killSwitches.checkAll(t, tenantId!, { agentId })).killed,
    ).toBe(false);
  });

  it('a concurrent platform engage and human stop both stay effective', async () => {
    const killSwitches = app.get(KillSwitchService);
    const suspension = app.get(PlatformSuspension);
    const t = await app.get(TenantDatabaseManager).getClient(tenantId!);
    const owner = await t.userProfile.findFirstOrThrow({
      where: { email: `${OWNER}@example.test` },
    });
    await Promise.all([
      suspension.engage(t, tenantId!, 'test'),
      killSwitches.activate(t, tenantId!, {
        scope: 'TENANT',
        targetId: null,
        activatedBy: owner.id,
        reason: 'race',
      }),
    ]);
    const rows = await t.killSwitch.findMany({
      where: { scope: 'TENANT', active: true },
    });
    expect(rows.map((r) => r.targetId).sort()).toEqual(
      [PLATFORM_SWITCH_TARGET, null].sort(),
    );
    expect(await suspension.release(t, tenantId!, 'test')).toBe(true);
    expect(
      await killSwitches.checkAll(t, tenantId!, { agentId: randomUUID() }),
    ).toMatchObject({ killed: true });
    await killSwitches.deactivate(t, tenantId!, {
      scope: 'TENANT',
      targetId: null,
      deactivatedBy: owner.id,
    });
  });

  it('the platform switch and its audit event commit together: no event, no switch', async () => {
    const suspension = app.get(PlatformSuspension);
    const audit = app.get(AuditService);
    const t = await app.get(TenantDatabaseManager).getClient(tenantId!);
    const spy = vi
      .spyOn(audit, 'recordInTransaction')
      .mockRejectedValueOnce(new Error('audit down'));
    try {
      await expect(suspension.engage(t, tenantId!, 'test')).rejects.toThrow(
        'audit down',
      );
    } finally {
      spy.mockRestore();
    }
    const row = await t.killSwitch.findUnique({
      where: { id: 'platform-suspension' },
    });
    expect(row?.active ?? false).toBe(false);
  });

  it('delete marks the tenant DELETED and its users are refused', async () => {
    const d = await http()
      .delete(`/platform/v1/tenants/${tenantId}`)
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    expect(body(d).status).toBe('DELETED');
    await http()
      .get('/users')
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(401);
    await http()
      .post(`/platform/v1/tenants/${tenantId}/resume`)
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(409);
  });
});
