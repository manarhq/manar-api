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
import { ControlPrismaService } from '../src/database/control-prisma.service';
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

  it('suspend cuts the tenant off at once; resume restores it', async () => {
    const s = await http()
      .post(`/platform/v1/tenants/${tenantId}/suspend`)
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    expect(body(s).status).toBe('SUSPENDED');
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
    await http()
      .get('/users')
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(200);
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
