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
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import {
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';

/**
 * Phase 15a (Section 70) mandatory scenarios: "Incident CRUD, status
 * transitions, tenant isolation, audit trail for create/status-change."
 * Mirrors `test/tenant-settings.e2e-spec.ts`'s simpler (no mTLS agent
 * listener needed) boilerplate.
 */
describe('Incidents (e2e)', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenantA: ProvisionedTenant;
  let tenantB: ProvisionedTenant;
  let tokenA: string;
  let tokenB: string;

  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `inc-${label}-${randomUUID().slice(0, 8)}`;
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
      name: `Incidents Test Tenant ${label}`,
    });
    if (!t.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }
    const secretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: t.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    const username = `inc-user-${label}-${randomUUID().slice(0, 8)}`;
    await createRealmUser(t.keycloakRealm, {
      username,
      email: `${username}@example.test`,
      password: USER_PASSWORD,
    });
    const token = await getUserToken({
      realm: t.keycloakRealm,
      clientId: t.keycloakClientId!,
      clientSecret: secretRef.reference,
      username,
      password: USER_PASSWORD,
    });
    return { tenant: t, token };
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

    const a = await provisionTenantWithUser('a');
    tenantA = a.tenant;
    tokenA = a.token;

    const b = await provisionTenantWithUser('b');
    tenantB = b.tenant;
    tokenB = b.token;
  }, 180_000);

  afterAll(async () => {
    await app.close();
    if (tenantA) await cleanupTenant(tenantA);
    if (tenantB) await cleanupTenant(tenantB);
    await control.$disconnect();
  }, 60_000);

  interface IncidentBody {
    id: string;
    title: string;
    description: string;
    severity: string;
    status: string;
    relatedCorrelationIds: string[];
    createdBy: string;
    createdAt: string;
    resolvedAt: string | null;
  }

  it('1. POST /incidents creates an incident (OPEN by default) and audits incident.created', async () => {
    const correlationId = randomUUID();
    const response = await request(app.getHttpServer() as App)
      .post('/incidents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        title: 'Suspected credential compromise',
        description: 'Anomalous EDR isolation activity on WS-042',
        severity: 'HIGH',
        relatedCorrelationIds: [correlationId],
      })
      .expect(201);

    const body = response.body as IncidentBody;
    expect(body.title).toBe('Suspected credential compromise');
    expect(body.severity).toBe('HIGH');
    expect(body.status).toBe('OPEN');
    expect(body.relatedCorrelationIds).toEqual([correlationId]);
    expect(body.resolvedAt).toBeNull();
    expect(body.id).toBeTruthy();

    const tenantClient = await tenantDatabaseManager.getClient(tenantA.id);
    const auditRows = await tenantClient.auditEvent.findMany({
      where: { eventType: 'incident.created' },
    });
    expect(auditRows.length).toBeGreaterThan(0);
    const match = auditRows.find(
      (r) => (r.data as { incidentId?: string }).incidentId === body.id,
    );
    expect(match).toBeDefined();
    expect((match!.actor as { type: string; id: string }).type).toBe('human');
  });

  it('2. GET /incidents lists, filters by status/severity, and cursor-paginates', async () => {
    await request(app.getHttpServer() as App)
      .post('/incidents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        title: 'Filter test A',
        description: 'x',
        severity: 'LOW',
      })
      .expect(201);
    await request(app.getHttpServer() as App)
      .post('/incidents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        title: 'Filter test B',
        description: 'x',
        severity: 'CRITICAL',
      })
      .expect(201);

    const criticalResponse = await request(app.getHttpServer() as App)
      .get('/incidents')
      .query({ severity: 'CRITICAL' })
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(200);
    const criticalBody = criticalResponse.body as { items: IncidentBody[] };
    expect(criticalBody.items.length).toBeGreaterThan(0);
    expect(criticalBody.items.every((i) => i.severity === 'CRITICAL')).toBe(
      true,
    );

    const openResponse = await request(app.getHttpServer() as App)
      .get('/incidents')
      .query({ status: 'OPEN' })
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(200);
    const openBody = openResponse.body as { items: IncidentBody[] };
    expect(openBody.items.length).toBeGreaterThan(0);
    expect(openBody.items.every((i) => i.status === 'OPEN')).toBe(true);

    const page1 = await request(app.getHttpServer() as App)
      .get('/incidents')
      .query({ limit: 1 })
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(200);
    const page1Body = page1.body as {
      items: IncidentBody[];
      nextCursor: string | null;
    };
    expect(page1Body.items).toHaveLength(1);
    expect(page1Body.nextCursor).not.toBeNull();
  });

  it('3. GET /incidents/:id returns one incident; 404 for an unknown id', async () => {
    const created = await request(app.getHttpServer() as App)
      .post('/incidents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ title: 'Get-by-id test', description: 'x', severity: 'MEDIUM' })
      .expect(201);
    const id = (created.body as IncidentBody).id;

    const got = await request(app.getHttpServer() as App)
      .get(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(200);
    expect((got.body as IncidentBody).id).toBe(id);

    await request(app.getHttpServer() as App)
      .get(`/incidents/${randomUUID()}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(404);
  });

  it('4. PATCH /incidents/:id transitions status OPEN -> INVESTIGATING -> RESOLVED (stamping resolvedAt) -> CLOSED (resolvedAt untouched), auditing each real status change', async () => {
    const created = await request(app.getHttpServer() as App)
      .post('/incidents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        title: 'Status transition test',
        description: 'x',
        severity: 'HIGH',
      })
      .expect(201);
    const id = (created.body as IncidentBody).id;

    const investigating = await request(app.getHttpServer() as App)
      .patch(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ status: 'INVESTIGATING' })
      .expect(200);
    expect((investigating.body as IncidentBody).status).toBe('INVESTIGATING');
    expect((investigating.body as IncidentBody).resolvedAt).toBeNull();

    const resolved = await request(app.getHttpServer() as App)
      .patch(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        status: 'RESOLVED',
        description: 'Root cause identified and contained',
      })
      .expect(200);
    const resolvedBody = resolved.body as IncidentBody;
    expect(resolvedBody.status).toBe('RESOLVED');
    expect(resolvedBody.description).toBe(
      'Root cause identified and contained',
    );
    expect(resolvedBody.resolvedAt).not.toBeNull();
    const resolvedAt = resolvedBody.resolvedAt;

    const closed = await request(app.getHttpServer() as App)
      .patch(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ status: 'CLOSED' })
      .expect(200);
    const closedBody = closed.body as IncidentBody;
    expect(closedBody.status).toBe('CLOSED');
    // The *first* resolution time is preserved, not overwritten by a later
    // transition away from RESOLVED -- see Incident.resolvedAt's doc
    // comment.
    expect(closedBody.resolvedAt).toBe(resolvedAt);

    const tenantClient = await tenantDatabaseManager.getClient(tenantA.id);
    const statusChangeEvents = await tenantClient.auditEvent.findMany({
      where: { eventType: 'incident.status_changed' },
    });
    const eventsForThisIncident = statusChangeEvents.filter(
      (r) => (r.data as { incidentId?: string }).incidentId === id,
    );
    expect(eventsForThisIncident).toHaveLength(3); // OPEN->INVESTIGATING, ->RESOLVED, ->CLOSED
    const transitions = eventsForThisIncident.map((r) => {
      const data = r.data as { previousStatus: string; newStatus: string };
      return `${data.previousStatus}->${data.newStatus}`;
    });
    expect(transitions).toContain('OPEN->INVESTIGATING');
    expect(transitions).toContain('INVESTIGATING->RESOLVED');
    expect(transitions).toContain('RESOLVED->CLOSED');
  });

  it('5. PATCH /incidents/:id with a non-status field only does NOT record incident.status_changed', async () => {
    const created = await request(app.getHttpServer() as App)
      .post('/incidents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        title: 'No-op status test',
        description: 'x',
        severity: 'LOW',
      })
      .expect(201);
    const id = (created.body as IncidentBody).id;

    const tenantClient = await tenantDatabaseManager.getClient(tenantA.id);
    const before = await tenantClient.auditEvent.count({
      where: { eventType: 'incident.status_changed' },
    });

    await request(app.getHttpServer() as App)
      .patch(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ title: 'Retitled, no status change' })
      .expect(200);

    const after = await tenantClient.auditEvent.count({
      where: { eventType: 'incident.status_changed' },
    });
    expect(after).toBe(before);

    // Setting status to its OWN current value (OPEN) is likewise not a
    // real transition.
    await request(app.getHttpServer() as App)
      .patch(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ status: 'OPEN' })
      .expect(200);
    const afterNoOpStatus = await tenantClient.auditEvent.count({
      where: { eventType: 'incident.status_changed' },
    });
    expect(afterNoOpStatus).toBe(before);
  });

  it('6. PATCH /incidents/:id rejects an empty body', async () => {
    const created = await request(app.getHttpServer() as App)
      .post('/incidents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({ title: 'Empty patch test', description: 'x', severity: 'LOW' })
      .expect(201);
    const id = (created.body as IncidentBody).id;

    await request(app.getHttpServer() as App)
      .patch(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .send({})
      .expect(400);
  });

  it('7. tenant isolation: an incident created in tenant A is invisible (404) from tenant B', async () => {
    const created = await request(app.getHttpServer() as App)
      .post('/incidents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        title: 'Tenant A only',
        description: 'x',
        severity: 'MEDIUM',
      })
      .expect(201);
    const id = (created.body as IncidentBody).id;

    // Visible from tenant A.
    await request(app.getHttpServer() as App)
      .get(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(200);

    // Not visible from tenant B -- structural per-tenant-database isolation
    // (docs/tenant-isolation.md), not an application-level filter.
    await request(app.getHttpServer() as App)
      .get(`/incidents/${id}`)
      .set('Authorization', `Bearer ${tokenB}`)
      .expect(404);

    // Tenant B's own list never includes tenant A's incident.
    const listB = await request(app.getHttpServer() as App)
      .get('/incidents')
      .set('Authorization', `Bearer ${tokenB}`)
      .expect(200);
    const listBBody = listB.body as { items: IncidentBody[] };
    expect(listBBody.items.some((i) => i.id === id)).toBe(false);
  });

  it('requires authentication', async () => {
    await request(app.getHttpServer() as App)
      .get('/incidents')
      .expect(401);
  });
});
