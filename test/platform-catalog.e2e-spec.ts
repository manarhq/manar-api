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
 * Per-tenant catalog (src/platform/catalog.*) against real Postgres, Redis and Keycloak: only the
 * platform client reads and writes it, a pack-bound task is refused until its pack is enabled,
 * and a feature staff turn off is off for the tenant's humans at once.
 */
describe('Platform catalog for manar-fleet (e2e)', () => {
  const suffix = PLATFORM_E2E_SUFFIX;
  const SLUG = `catalog-e2e-${suffix}`;
  const OWNER = `cowner-${suffix}`;
  const PASSWORD = 'Passw0rd!Test';

  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let platformClient: { uuid: string; secret: string };
  let platformToken: string;
  let ownerToken: string;
  let tenantId: string | undefined;
  let agentId: string;
  const http = () => request(app.getHttpServer());
  const catalogUrl = () => `/platform/v1/tenants/${tenantId}/catalog`;
  const patch = (body: unknown) =>
    http()
      .patch(catalogUrl())
      .set('Authorization', `Bearer ${platformToken}`)
      .send(body as object);
  const createTask = (packId?: string) =>
    http()
      .post('/tasks')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        name: 'catalog e2e',
        assignedAgentId: agentId,
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        ...(packId ? { packId } : {}),
      });

  beforeAll(async () => {
    platformClient = await createPlatformClient(
      PLATFORM_E2E_CLIENT_ID,
      PLATFORM_E2E_ROLE,
    );
    platformToken = await getClientCredentialsToken(
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

    const created = await http()
      .post('/platform/v1/tenants')
      .set('Authorization', `Bearer ${platformToken}`)
      .send({ slug: SLUG, name: 'Catalog E2E' })
      .expect(201);
    tenantId = (created.body as { id: string }).id;
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
    const agent = await http()
      .post('/agents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ slug: `cat-agent-${suffix}`, displayName: 'Catalog agent' })
      .expect(201);
    agentId = (agent.body as { id: string }).id;
  }, 180_000);

  afterAll(async () => {
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
    delete process.env.PLATFORM_API_ISSUER;
    delete process.env.PLATFORM_API_CLIENT_ID;
    delete process.env.PLATFORM_API_ROLE;
  }, 60_000);

  it('an unmanaged tenant keeps every feature on, no pack enabled, the default model', async () => {
    const res = await http()
      .get(catalogUrl())
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    expect(res.body).toMatchObject({
      tenantId,
      managed: false,
      features: {
        assistant: true,
        watcher: true,
        packs: true,
        llm_proxy: true,
      },
      packs: [],
      model: null,
      connectors: [],
    });
  });

  it('only the platform client reads or writes it; a tenant token never does', async () => {
    await http().get(catalogUrl()).expect(401);
    await http()
      .get(catalogUrl())
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(401);
    await http()
      .patch(catalogUrl())
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ features: { assistant: true } })
      .expect(401);
  });

  it('rejects an unknown feature, an unknown provider and an empty change', async () => {
    await patch({ features: { billing: true } }).expect(400);
    await patch({
      model: {
        provider: 'openai',
        model: 'x',
        uaeResidency: true,
        monthlyTokenQuota: null,
      },
    }).expect(400);
    await patch({}).expect(400);
  });

  it('refuses a pack-bound task until the pack is enabled, then accepts it', async () => {
    const refused = await createTask('it-helpdesk').expect(403);
    expect(refused.body).toMatchObject({ reason: 'pack_not_enabled' });
    await createTask().expect(201);

    const res = await patch({
      packs: [{ id: 'it-helpdesk', version: 1, enabled: true }],
    }).expect(200);
    expect(res.body).toMatchObject({
      managed: true,
      packs: [{ id: 'it-helpdesk', version: 1, enabled: true }],
    });
    await createTask('it-helpdesk').expect(201);

    await patch({ features: { packs: false } }).expect(200);
    const off = await createTask('it-helpdesk').expect(403);
    expect(off.body).toMatchObject({ reason: 'packs_disabled' });
    await patch({ features: { packs: true } }).expect(200);
  });

  it('turns the assistant off for the tenant at once, and the change is in the tenant audit chain', async () => {
    await patch({ features: { assistant: false } }).expect(200);
    const res = await http()
      .post('/assistant/chat')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ messages: [{ role: 'user', content: 'hello' }], locale: 'en' })
      .expect(403);
    expect(res.body).toMatchObject({ reason: 'assistant_disabled' });

    const db = await app.get(TenantDatabaseManager).getClient(tenantId!);
    const events = await db.auditEvent.findMany({
      where: { eventType: 'catalog.updated' },
    });
    expect(events.length).toBeGreaterThan(0);
  });

  it('stores the model route and reports this month of token use', async () => {
    const res = await patch({
      model: {
        provider: 'ollama',
        model: 'qwen3.5:9b',
        uaeResidency: true,
        monthlyTokenQuota: 2_000_000,
      },
    }).expect(200);
    expect(res.body).toMatchObject({
      model: { provider: 'ollama', model: 'qwen3.5:9b', uaeResidency: true },
      usage: { month: new Date().toISOString().slice(0, 7), tokens: 0 },
    });
  });

  it('concurrent changes to different packs and flags all stick (row lock)', async () => {
    const packs = Array.from({ length: 8 }, (_, i) => `conc-pack-${i}`);
    const results = await Promise.all([
      ...packs.map((id) =>
        patch({ packs: [{ id, version: 1, enabled: true }] }),
      ),
      patch({ features: { watcher: false } }),
      patch({ features: { llm_proxy: false } }),
    ]);
    for (const r of results) expect(r.status).toBe(200);
    const res = await http()
      .get(catalogUrl())
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    const body = res.body as {
      packs: { id: string }[];
      features: Record<string, boolean>;
    };
    for (const id of packs) expect(body.packs.map((p) => p.id)).toContain(id);
    expect(body.features).toMatchObject({ watcher: false, llm_proxy: false });
    await patch({ features: { watcher: true, llm_proxy: true } }).expect(200);
  });

  it('binds an agent to a pack: its tasks get the pack, another pack is refused, and disabling stops it', async () => {
    await patch({
      packs: [
        { id: 'it-helpdesk', version: 1, enabled: true, agents: [agentId] },
      ],
    }).expect(200);
    const view = await http()
      .get(catalogUrl())
      .set('Authorization', `Bearer ${platformToken}`)
      .expect(200);
    expect((view.body as { agents: { id: string }[] }).agents).toEqual([
      expect.objectContaining({ id: agentId }),
    ]);

    const created = await createTask().expect(201);
    const db = await app.get(TenantDatabaseManager).getClient(tenantId!);
    const task = await db.task.findUniqueOrThrow({
      where: { id: (created.body as { id: string }).id },
    });
    expect(task.packId).toBe('it-helpdesk');

    await patch({
      packs: [{ id: 'coding-agents', version: 1, enabled: true }],
    }).expect(200);
    const other = await createTask('coding-agents').expect(403);
    expect(other.body).toMatchObject({ reason: 'pack_mismatch' });

    // Omitting agents on a later change keeps the binding.
    await patch({
      packs: [{ id: 'it-helpdesk', version: 1, enabled: false }],
    }).expect(200);
    const off = await createTask().expect(403);
    expect(off.body).toMatchObject({ reason: 'pack_not_enabled' });
  });
});
