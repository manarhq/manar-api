import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import { generateAgentCsr } from '@manar/sdk-node';
import { AppModule } from '../src/app.module';
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

/** Hosts over HTTP (docs/hosts.md): roles, the once-shown key, public registration. */
describe('Hosts HTTP (e2e)', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  type Provisioned = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: Provisioned;
  const tokens: Record<'owner' | 'auditor' | 'plain', string> = {
    owner: '',
    auditor: '',
    plain: '',
  };
  const PASSWORD = 'Passw0rd!Test';
  const server = () => app.getHttpServer() as App;

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
    tenant = await app.get(TenantProvisioningService).provisionTenant({
      slug: `hostshttp-${randomUUID().slice(0, 8)}`,
      name: 'Hosts HTTP',
    });
    const secret = (
      await control.secretReference.findFirstOrThrow({
        where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
      })
    ).reference;
    const realm = tenant.keycloakRealm!;
    for (const [who, role] of [
      ['owner', 'TENANT_OWNER'],
      ['auditor', 'AUDITOR'],
      ['plain', null],
    ] as const) {
      const username = `h${who}-${randomUUID().slice(0, 6)}`;
      const id = await createRealmUser(realm, {
        username,
        email: `${username}@example.test`,
        password: PASSWORD,
      });
      if (role) await assignRealmRole(realm, id, role);
      tokens[who] = await getUserToken({
        realm,
        clientId: tenant.keycloakClientId!,
        clientSecret: secret,
        username,
        password: PASSWORD,
      });
    }
  }, 120_000);

  afterAll(async () => {
    await app.close();
    if (tenant) {
      if (tenant.keycloakRealm) await deleteRealm(tenant.keycloakRealm);
      const pg = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await pg.connect();
      await pg.query(
        `DROP DATABASE IF EXISTS "${tenant.databaseBinding!.databaseName}" WITH (FORCE)`,
      );
      await pg.end();
      await control.tenantDatabaseBinding.deleteMany({
        where: { tenantId: tenant.id },
      });
      await control.secretReference.deleteMany({
        where: { tenantId: tenant.id },
      });
      await control.tenant.deleteMany({ where: { id: tenant.id } });
    }
  }, 60_000);

  it('runs the whole flow with the right roles at each step', async () => {
    const as = (who: keyof typeof tokens) => `Bearer ${tokens[who]}`;

    await request(server())
      .post('/host-groups')
      .set('Authorization', as('plain'))
      .send({ name: 'Dev' })
      .expect(403);
    const group = (
      await request(server())
        .post('/host-groups')
        .set('Authorization', as('owner'))
        .send({ name: 'Dev' })
        .expect(201)
    ).body as { id: string };

    const created = (
      await request(server())
        .post('/install-keys')
        .set('Authorization', as('owner'))
        .send({ hostGroupId: group.id, label: 'dev laptops', maxUses: 5 })
        .expect(201)
    ).body as {
      id: string;
      installKey: string;
      keyHash?: string;
      expiresAt: string;
      maxUses: number;
    };
    expect(created.installKey).toMatch(/^mik_/);
    expect(created.keyHash).toBeUndefined();
    // No "never expires": 24 hours unless the admin picks 1 hour to 30 days.
    const left = new Date(created.expiresAt).getTime() - Date.now();
    expect(left).toBeGreaterThan(23 * 3_600_000);
    expect(left).toBeLessThanOrEqual(24 * 3_600_000);
    expect(created.maxUses).toBe(5);
    await request(server())
      .post('/install-keys')
      .set('Authorization', as('owner'))
      .send({
        hostGroupId: group.id,
        label: 'forever',
        expiresAt: new Date(Date.now() + 31 * 86_400_000).toISOString(),
      })
      .expect(400);
    const listed = await request(server())
      .get('/install-keys')
      .set('Authorization', as('auditor'))
      .expect(200);
    expect(JSON.stringify(listed.body)).not.toContain(created.installKey);
    expect(JSON.stringify(listed.body)).not.toContain('keyHash');

    // The machine side: public, the install key is the credential.
    const { csrPem } = await generateAgentCsr(
      `host://${tenant.slug}/http-box-1`,
    );
    const body = {
      installKey: created.installKey,
      csr: csrPem,
      machineId: 'http-box-1',
      hostname: 'HTTP-BOX-1',
      os: 'Ubuntu 24.04',
      keyType: 'SOFTWARE',
    };
    await request(server())
      .post('/hosts/register')
      .send({ ...body, installKey: `mik_${tenant.slug}_${'x'.repeat(43)}` })
      .expect(401);
    const registered = (
      await request(server()).post('/hosts/register').send(body).expect(201)
    ).body as { hostId: string; status: string };
    expect(registered.status).toBe('PENDING');

    const hosts = await request(server())
      .get('/hosts?status=PENDING')
      .set('Authorization', as('auditor'))
      .expect(200);
    expect(
      (hosts.body as { items: { id: string }[] }).items.map((h) => h.id),
    ).toContain(registered.hostId);
    await request(server())
      .post(`/hosts/${registered.hostId}/approve`)
      .set('Authorization', as('auditor'))
      .expect(403);
    const approved = await request(server())
      .post(`/hosts/${registered.hostId}/approve`)
      .set('Authorization', as('owner'))
      .expect(201);
    expect((approved.body as { status: string }).status).toBe('APPROVED');
    await request(server())
      .post(`/hosts/${registered.hostId}/reject`)
      .set('Authorization', as('owner'))
      .expect(409);

    const client = await app.get(TenantDatabaseManager).getClient(tenant.id);
    expect(
      await client.auditEvent.count({ where: { eventType: 'host.approved' } }),
    ).toBe(1);
  }, 60_000);

  it('refuses an org-unit cycle and a malformed address range', async () => {
    const as = `Bearer ${tokens.owner}`;
    const parent = (
      await request(server())
        .post('/org-units')
        .set('Authorization', as)
        .send({ name: 'IT' })
        .expect(201)
    ).body as { id: string };
    const child = (
      await request(server())
        .post('/org-units')
        .set('Authorization', as)
        .send({ name: 'Ops', parentId: parent.id })
        .expect(201)
    ).body as { id: string };
    await request(server())
      .patch(`/org-units/${parent.id}`)
      .set('Authorization', as)
      .send({ parentId: child.id })
      .expect(400);
    await request(server())
      .post('/host-approval-rules')
      .set('Authorization', as)
      .send({ cidrs: ['10.0.0.0/'] })
      .expect(400);
  }, 60_000);
});
