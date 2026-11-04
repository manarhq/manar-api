import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { monthOf } from '../src/billing/plans';
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
 * Pay-as-you-go pricing (workspace spec 2026-11-04-payg) through the real HTTP app, Keycloak and
 * PostgreSQL: the AI allowance pauses AI answers, never anything else; a use with no answer is
 * given back; only the owner changes the wallet; Free cannot buy credits.
 */
describe('pay-as-you-go metering (e2e)', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let provisioning: TenantProvisioningService;
  let tenant: Awaited<ReturnType<TenantProvisioningService['provisionTenant']>>;
  let owner = '';
  let reader = '';
  const PASSWORD = 'Passw0rd!Test';

  const http = () => request(app.getHttpServer());
  const setAiUsed = (aiUsed: number) =>
    control.usageMonth.upsert({
      where: { tenantId_month: { tenantId: tenant.id, month: monthOf() } },
      create: { tenantId: tenant.id, month: monthOf(), aiUsed },
      update: { aiUsed },
    });
  const aiUsed = async () =>
    (
      await control.usageMonth.findUniqueOrThrow({
        where: { tenantId_month: { tenantId: tenant.id, month: monthOf() } },
      })
    ).aiUsed;

  async function user(role: string): Promise<string> {
    const secret = await control.secretReference.findFirstOrThrow({
      where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    const username = `payg-${role.toLowerCase()}-${randomUUID().slice(0, 8)}`;
    const id = await createRealmUser(tenant.keycloakRealm!, {
      username,
      email: `${username}@example.test`,
      password: PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm!, id, role);
    return getUserToken({
      realm: tenant.keycloakRealm!,
      clientId: tenant.keycloakClientId!,
      clientSecret: secret.reference,
      username,
      password: PASSWORD,
    });
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
      slug: `payg-${randomUUID().slice(0, 8)}`,
      name: 'PAYG Test Tenant',
    });
    owner = await user('TENANT_OWNER');
    reader = await user('READ_ONLY');
  }, 180_000);

  afterAll(async () => {
    await app.close();
    if (!tenant) return;
    const where = { tenantId: tenant.id };
    await control.usageEvent.deleteMany({ where });
    await control.usageMonth.deleteMany({ where });
    await control.creditLot.deleteMany({ where });
    await control.creditWallet.deleteMany({ where });
    if (tenant.keycloakRealm) await deleteRealm(tenant.keycloakRealm);
    const name = tenant.databaseBinding?.databaseName;
    if (name) {
      const pg = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await pg.connect();
      await pg.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
      await pg.end();
    }
    await control.tenantEntitlement.deleteMany({ where });
    await control.tenantDatabaseBinding.deleteMany({ where });
    await control.secretReference.deleteMany({ where });
    await control.tenant.deleteMany({ where: { id: tenant.id } });
    await control.$disconnect();
  }, 60_000);

  it('the usage page shows the Free allowance; only owners and security admins see it', async () => {
    const res = await http()
      .get('/billing/usage')
      .set('Authorization', `Bearer ${owner}`)
      .expect(200);
    expect(res.body).toMatchObject({
      plan: 'free',
      allowance: { ai: { included: 20 }, cloudMinutes: { included: 0 } },
      wallet: { available: false },
    });
    await http()
      .get('/billing/usage')
      .set('Authorization', `Bearer ${reader}`)
      .expect(403);
  });

  it('an AI action with no answer is given back; the allowance used up pauses AI with a 402', async () => {
    await setAiUsed(19);
    // No model is configured in this stack, so the answer is `available: false`: not charged.
    const first = await http()
      .post('/incidents/summarize')
      .set('Authorization', `Bearer ${owner}`)
      .send({
        title: 'Odd sign-in',
        description: 'A sign-in from a new place',
      });
    expect(first.status).toBeLessThan(300);
    expect(await aiUsed()).toBe(19);

    await setAiUsed(20);
    const paused = await http()
      .post('/incidents/summarize')
      .set('Authorization', `Bearer ${owner}`)
      .send({ title: 'Odd sign-in', description: 'A sign-in from a new place' })
      .expect(402);
    expect(JSON.stringify(paused.body)).toContain('allowance_used');
    expect(JSON.stringify(paused.body)).toContain('Protection is still on');
  });

  it('with AI paused, everything that is not a paid extra keeps working', async () => {
    await setAiUsed(20);
    await http()
      .post('/incidents')
      .set('Authorization', `Bearer ${owner}`)
      .send({
        title: 'Still works',
        description: 'Not metered',
        severity: 'LOW',
      })
      .expect(201);
    await http()
      .get('/audit')
      .set('Authorization', `Bearer ${owner}`)
      .expect(200);
  });

  it('Free cannot buy credits; only the owner sets the cap', async () => {
    await http()
      .post('/billing/credits')
      .set('Authorization', `Bearer ${owner}`)
      .send({ packs: 1 })
      .expect(403);
    await control.tenantEntitlement.upsert({
      where: { tenantId: tenant.id },
      create: { tenantId: tenant.id, plan: 'pro', status: 'active' },
      update: { plan: 'pro', status: 'active' },
    });
    await http()
      .put('/billing/wallet')
      .set('Authorization', `Bearer ${reader}`)
      .send({ capUsd: 1000 })
      .expect(403);
    await http()
      .put('/billing/wallet')
      .set('Authorization', `Bearer ${owner}`)
      .send({ capUsd: 40, extra: true })
      .expect(400);
    const res = await http()
      .put('/billing/wallet')
      .set('Authorization', `Bearer ${owner}`)
      .send({ capUsd: 40, autoTopUp: true })
      .expect(200);
    const body = res.body as {
      wallet: object;
      allowance: { ai: { included: number } };
    };
    expect(body.wallet).toMatchObject({ capCredits: 8000, autoTopUp: true });
    expect(body.allowance.ai.included).toBe(300);
  });
});
