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
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KillSwitchService } from '../src/kill-switches/kill-switch.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import {
  assignRealmRole,
  createPlatformClient,
  createRealmUser,
  getUserToken,
  deletePlatformClient,
  deleteRealm,
  getClientCredentialsToken,
} from './support/keycloak-test-helpers';

/**
 * Admin v2 ops routes of the platform API: the deployment's platform kill switch (a release names
 * the engagement it ends), a tenant's ops view and its audit chain check. The platform kill switch
 * is deployment-wide: run this only against a control database of your own, never the demo's.
 */
interface OpsBody {
  id: string;
  code: string;
  engagementId: string;
  activatedAt: string;
  killSwitches: unknown[];
  quarantines: unknown[];
  usage: { months: { month: string }[] };
  credentials: unknown[];
  eventCount: number;
  valid: boolean;
  brokenAt: string | null;
}
const b = (r: { body: unknown }) => r.body as OpsBody;

describe('Platform API ops routes (e2e)', () => {
  const suffix = PLATFORM_E2E_SUFFIX;
  const SLUG = `platform-ops-${suffix}`;
  const KV_PATH = `tools/e2e-ops-${suffix}`;
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let platformClient: { uuid: string; secret: string };
  let token: string;
  let tenantId: string | undefined;
  const http = () => request(app.getHttpServer());
  const auth = () => ({ Authorization: `Bearer ${token}` });

  async function openbao(method: string, path: string, body?: unknown) {
    const res = await fetch(`${process.env.OPENBAO_ADDR}/v1/${path}`, {
      method,
      headers: {
        'X-Vault-Token': process.env.OPENBAO_TOKEN!,
        'content-type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok && res.status !== 404)
      throw new Error(`OpenBao ${method} ${path}: ${res.status}`);
  }

  beforeAll(async () => {
    platformClient = await createPlatformClient(
      PLATFORM_E2E_CLIENT_ID,
      PLATFORM_E2E_ROLE,
    );
    token = await getClientCredentialsToken(
      PLATFORM_E2E_CLIENT_ID,
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
    // Never leave the deployment-wide switch on.
    await control?.platformKillSwitch.updateMany({
      where: { id: 'singleton' },
      data: { active: false },
    });
    await openbao('DELETE', `secret/metadata/${KV_PATH}`).catch(() => {});
    await app?.close();
    await deletePlatformClient(platformClient?.uuid, PLATFORM_E2E_ROLE);
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
  }, 60_000);

  it('every ops route needs the platform token', async () => {
    await http().get('/platform/v1/kill-switch').expect(401);
    await http()
      .post('/platform/v1/kill-switch/engage')
      .send({ reason: 'x', staff: 'y' })
      .expect(401);
    await http()
      .post('/platform/v1/kill-switch/release')
      .send({ staff: 'y', expectedEngagementId: new Date().toISOString() })
      .expect(401);
  });

  describe('platform kill switch', () => {
    let first: string;

    it('engages for every tenant and names the engagement', async () => {
      const off = await http()
        .get('/platform/v1/kill-switch')
        .set(auth())
        .expect(200);
      expect(off.body).toMatchObject({ active: false, engagementId: null });
      const on = await http()
        .post('/platform/v1/kill-switch/engage')
        .set(auth())
        .send({ reason: 'e2e incident A', staff: 'Mohamed' })
        .expect(200);
      expect(on.body).toMatchObject({
        active: true,
        reason: 'e2e incident A',
        activatedBy: `${PLATFORM_E2E_CLIENT_ID}: Mohamed`,
      });
      first = b(on).engagementId;
      expect(first).toBe(b(on).activatedAt);
      await http()
        .post('/platform/v1/kill-switch/engage')
        .set(auth())
        .send({ reason: 'no', staff: 'Mohamed' })
        .expect(400);
    });

    it('a release for an earlier engagement is refused and the new stop stays on', async () => {
      await new Promise((r) => setTimeout(r, 5));
      const again = await http()
        .post('/platform/v1/kill-switch/engage')
        .set(auth())
        .send({ reason: 'e2e incident B', staff: 'Mohamed' })
        .expect(200);
      expect(b(again).engagementId).not.toBe(first);
      const stale = await http()
        .post('/platform/v1/kill-switch/release')
        .set(auth())
        .send({ staff: 'Ali', expectedEngagementId: first })
        .expect(409);
      expect(b(stale).code).toBe('engagement_changed');
      const state = await http()
        .get('/platform/v1/kill-switch')
        .set(auth())
        .expect(200);
      expect(state.body).toMatchObject({
        active: true,
        reason: 'e2e incident B',
      });
      first = b(again).engagementId;
    });

    it('releases the named engagement, once', async () => {
      const off = await http()
        .post('/platform/v1/kill-switch/release')
        .set(auth())
        .send({
          staff: 'Ali',
          proposedBy: 'Mohamed',
          expectedEngagementId: first,
        })
        .expect(200);
      expect(off.body).toMatchObject({
        active: false,
        engagementId: null,
        deactivatedBy: `${PLATFORM_E2E_CLIENT_ID}: Ali`,
      });
      await http()
        .post('/platform/v1/kill-switch/release')
        .set(auth())
        .send({ staff: 'Ali', expectedEngagementId: first })
        .expect(409);
      await http()
        .post('/platform/v1/kill-switch/release')
        .set(auth())
        .send({ staff: 'Ali' })
        .expect(400);
    });
  });

  describe('tenant ops view and audit chain check', () => {
    it('provisions a tenant', async () => {
      const res = await http()
        .post('/platform/v1/tenants')
        .set(auth())
        .send({ slug: SLUG, name: 'Platform Ops E2E' })
        .expect(201);
      tenantId = b(res).id;
    }, 120_000);

    it('the legacy route still engages, but can no longer release the platform switch alone', async () => {
      const tenant = await control.tenant.findUniqueOrThrow({
        where: { id: tenantId },
      });
      const secret = await control.secretReference.findFirstOrThrow({
        where: { tenantId, kind: 'KEYCLOAK_CLIENT_SECRET' },
      });
      const user = `ops-admin-${suffix}`;
      const password = 'Passw0rd!Test';
      const id = await createRealmUser(SLUG, {
        username: user,
        email: `${user}@example.test`,
        password,
      });
      await assignRealmRole(SLUG, id, 'SECURITY_ADMIN');
      const admin = await getUserToken({
        realm: SLUG,
        clientId: tenant.keycloakClientId!,
        clientSecret: secret.reference,
        username: user,
        password,
      });
      const operator =
        process.env.PLATFORM_KILL_SWITCH_OPERATOR_TOKEN ??
        'dev-only-platform-kill-switch-operator-token-change-me';
      // Stopping stays easy.
      await http()
        .post('/kill-switches/platform')
        .set('Authorization', `Bearer ${admin}`)
        .set('X-Platform-Operator-Token', operator)
        .send({ reason: 'e2e legacy engage' })
        .expect(201);
      const refused = await http()
        .post('/kill-switches/platform/deactivate')
        .set('Authorization', `Bearer ${admin}`)
        .set('X-Platform-Operator-Token', operator)
        .expect(403);
      expect(b(refused).code).toBe('platform_release_requires_two_person');
      const state = await http()
        .get('/platform/v1/kill-switch')
        .set(auth())
        .expect(200);
      expect(b(state)).toMatchObject({ active: true });
      // The two-person path still ends it, for the named engagement.
      await http()
        .post('/platform/v1/kill-switch/release')
        .set(auth())
        .send({ staff: 'Ali', expectedEngagementId: b(state).engagementId })
        .expect(200);
    }, 60_000);

    it('reports kill switches, quarantines, monthly decisions and credential expiry', async () => {
      const db = await app.get(TenantDatabaseManager).getClient(tenantId!);
      await db.tool.create({
        data: {
          name: `graph-${suffix}`,
          type: 'IAM',
          vendor: 'Microsoft',
          baseEndpoint: 'https://graph.microsoft.com',
          protocol: 'HTTP',
          credentialReference: { provider: 'OPENBAO', reference: KV_PATH },
        },
      });
      await app.get(OpenBaoKvClient).writeSecret(KV_PATH, { value: 'x' });
      await openbao('POST', `secret/metadata/${KV_PATH}`, {
        custom_metadata: { expires_at: '2026-11-08T00:00:00Z' },
      });

      const res = await http()
        .get(`/platform/v1/tenants/${tenantId}/ops`)
        .set(auth())
        .expect(200);
      expect(b(res).killSwitches).toEqual([]);
      expect(b(res).quarantines).toEqual([]);
      expect(b(res).usage.months).toHaveLength(6);
      expect(b(res).usage.months.at(-1)?.month).toBe(
        new Date().toISOString().slice(0, 7),
      );
      expect(b(res).usage).toMatchObject({
        agentsEnrolled: 0,
        agentsTotal: 0,
      });
      expect(b(res).credentials).toEqual([
        {
          tool: `graph-${suffix}`,
          vendor: 'Microsoft',
          enabled: true,
          expiresAt: '2026-11-08T00:00:00.000Z',
        },
      ]);
      // The secret value never appears.
      expect(JSON.stringify(res.body)).not.toContain('"value"');
    });

    it('shows the platform suspension as a platform kill switch', async () => {
      await http()
        .post(`/platform/v1/tenants/${tenantId}/suspend`)
        .set(auth())
        .expect(200);
      // A suspended tenant has no live ops view.
      await http()
        .get(`/platform/v1/tenants/${tenantId}/ops`)
        .set(auth())
        .expect(404);
      await http()
        .post(`/platform/v1/tenants/${tenantId}/resume`)
        .set(auth())
        .expect(200);
      const db = await app.get(TenantDatabaseManager).getClient(tenantId!);
      const profile = await db.userProfile.findFirstOrThrow();
      await app.get(KillSwitchService).activate(db, tenantId!, {
        scope: 'TENANT',
        targetId: null,
        reason: 'e2e human stop',
        activatedBy: profile.id,
      });
      const res = await http()
        .get(`/platform/v1/tenants/${tenantId}/ops`)
        .set(auth())
        .expect(200);
      expect(b(res).killSwitches).toEqual([
        expect.objectContaining({ scope: 'TENANT', platform: false }),
      ]);
    });

    it('checks the audit chain: valid, with the event count', async () => {
      const res = await http()
        .post(`/platform/v1/tenants/${tenantId}/audit/verify`)
        .set(auth())
        .expect(200);
      expect(res.body).toMatchObject({ valid: true, brokenAt: null });
      expect(b(res).eventCount).toBeGreaterThan(0);
    });

    it('detects an edited audit event', async () => {
      const binding = await control.tenantDatabaseBinding.findUniqueOrThrow({
        where: { tenantId },
      });
      const url = new URL(process.env.TENANT_DB_BASE_URL!);
      url.pathname = `/${binding.databaseName}`;
      const pg = new PgClient({ connectionString: url.toString() });
      await pg.connect();
      try {
        // The owner role can bypass the append-only trigger for this test only.
        await pg.query('ALTER TABLE audit_events DISABLE TRIGGER USER');
        await pg.query(
          `UPDATE audit_events SET data = '{"edited":true}' WHERE sequence = (SELECT min(sequence) FROM audit_events)`,
        );
        await pg.query('ALTER TABLE audit_events ENABLE TRIGGER USER');
      } finally {
        await pg.end();
      }
      const res = await http()
        .post(`/platform/v1/tenants/${tenantId}/audit/verify`)
        .set(auth())
        .expect(200);
      expect(b(res).valid).toBe(false);
      expect(b(res).brokenAt).toBeTruthy();
    });
  });
});
