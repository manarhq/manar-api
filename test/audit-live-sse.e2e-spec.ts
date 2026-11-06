import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import request from 'supertest';
import { App } from 'supertest/types';
import { RedisPubSubService } from '../src/audit/live/redis-pubsub.service';
import { AppModule } from '../src/app.module';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import type { DomainEventEnvelope } from '../src/audit/domain-event-envelope';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getUserToken,
} from './support/keycloak-test-helpers';

/**
 * Phase 9b (Live SSE, Section 62) — the design spec's mandatory scenario:
 * "a real triggered action... while an SSE connection is open, and asserts
 * the event arrives over that connection — not a polling-based fake," AND
 * "a *different* tenant's open connection does NOT receive it (tenant
 * isolation on the live feed — this is a real invariant, not a
 * nice-to-have, test it explicitly)."
 *
 * The real triggered action here is `POST /tasks` (`task.created`) via two
 * simple human-JWT-gated calls (create an agent, then a task) — chosen
 * over an authorization *denial* (the design spec's own example) because
 * it's equally real/audit-worthy while avoiding pulling agent mTLS/OpenBao
 * PKI enrollment machinery into a test that's really exercising the SSE
 * pipeline, not `AuthorizationService` itself (already covered by
 * `test/audit-retrofit.e2e-spec.ts`).
 */
describe('Live audit-event SSE feed (e2e)', () => {
  let app: NestFastifyApplication;
  let endpoint: string;
  let control: ControlPrismaService;
  let provisioning: TenantProvisioningService;

  const ADMIN_USERNAME_A = `sse-admin-a-${randomUUID().slice(0, 8)}`;
  const ADMIN_USERNAME_B = `sse-admin-b-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenantA: ProvisionedTenant;
  let tenantB: ProvisionedTenant;
  let tokenA: string;
  let tokenB: string;

  function uniqueSlug(label: string): string {
    return `sse-${label}-${randomUUID().slice(0, 8)}`;
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

  async function provisionAdminUser(
    tenant: ProvisionedTenant,
    username: string,
    role = 'SECURITY_ADMIN',
  ): Promise<string> {
    if (!tenant.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }
    const clientSecretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    const userId = await createRealmUser(tenant.keycloakRealm, {
      username,
      email: `${username}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenant.keycloakRealm, userId, role);
    return getUserToken({
      realm: tenant.keycloakRealm,
      clientId: tenant.keycloakClientId!,
      clientSecret: clientSecretRef.reference,
      username,
      password: USER_PASSWORD,
    });
  }

  /** Opens a live SSE connection and incrementally parses `audit-event` frames into `received`. */
  function openLiveConnection(
    token: string,
    query = '',
  ): {
    received: DomainEventEnvelope[];
    close: () => void;
  } {
    const received: DomainEventEnvelope[] = [];
    const controller = new AbortController();

    void (async () => {
      let response: Response;
      try {
        response = await fetch(`${endpoint}/events/live${query}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
      } catch {
        return;
      }
      const body = response.body;
      if (!body) return;
      const reader = body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let separatorIndex: number;
          while ((separatorIndex = buffer.indexOf('\n\n')) !== -1) {
            const frame = buffer.slice(0, separatorIndex);
            buffer = buffer.slice(separatorIndex + 2);
            const dataLine = frame
              .split('\n')
              .find((line) => line.startsWith('data: '));
            if (dataLine) {
              received.push(
                JSON.parse(
                  dataLine.slice('data: '.length),
                ) as DomainEventEnvelope,
              );
            }
          }
        }
      } catch {
        // Connection aborted/closed — expected on cleanup.
      }
    })();

    return { received, close: () => controller.abort() };
  }

  async function waitUntil(
    predicate: () => boolean,
    timeoutMs: number,
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (predicate()) return;
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
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
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address() as AddressInfo;
    endpoint = `http://127.0.0.1:${address.port}`;

    control = app.get(ControlPrismaService);
    provisioning = moduleFixture.get(TenantProvisioningService);

    tenantA = await provisioning.provisionTenant({
      slug: uniqueSlug('a'),
      name: 'SSE Test Tenant A',
    });
    tenantB = await provisioning.provisionTenant({
      slug: uniqueSlug('b'),
      name: 'SSE Test Tenant B',
    });

    tokenA = await provisionAdminUser(tenantA, ADMIN_USERNAME_A);
    tokenB = await provisionAdminUser(tenantB, ADMIN_USERNAME_B);
  }, 120_000);

  afterAll(async () => {
    if (tenantA?.keycloakRealm) await deleteRealm(tenantA.keycloakRealm);
    if (tenantB?.keycloakRealm) await deleteRealm(tenantB.keycloakRealm);
    for (const tenant of [tenantA, tenantB]) {
      if (!tenant?.databaseBinding) continue;
      await dropRealDatabase(tenant.databaseBinding.databaseName);
      await control.tenantDatabaseBinding.deleteMany({
        where: { tenantId: tenant.id },
      });
      await control.secretReference.deleteMany({
        where: { tenantId: tenant.id },
      });
      await control.tenant.deleteMany({ where: { id: tenant.id } });
    }
    await app.close();
  }, 60_000);

  it("a real task.created event arrives on the correct tenant's open connection, and a different tenant's connection never receives it", async () => {
    const connectionA = openLiveConnection(tokenA);
    const connectionB = openLiveConnection(tokenB);

    // Give both SSE connections + their Redis SUBSCRIBEs a moment to
    // actually establish before triggering the real action — otherwise
    // a fast publish could race a not-yet-subscribed connection.
    await new Promise((resolve) => setTimeout(resolve, 1_500));

    const agentResponse = await request(app.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        slug: `sse-agt-${randomUUID().slice(0, 8)}`,
        displayName: 'SSE Test Agent',
      })
      .expect(201);
    const agentId = (agentResponse.body as { id: string }).id;

    const taskResponse = await request(app.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        name: 'SSE trigger task',
        assignedAgentId: agentId,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      })
      .expect(201);
    const taskId = (taskResponse.body as { id: string }).id;

    await waitUntil(
      () =>
        connectionA.received.some(
          (envelope) =>
            envelope.eventType === 'task.created' &&
            envelope.tenantId === tenantA.id &&
            (envelope.data as { taskId?: string } | undefined)?.taskId ===
              taskId,
        ),
      20_000,
    );

    const matchOnA = connectionA.received.find(
      (envelope) =>
        envelope.eventType === 'task.created' &&
        (envelope.data as { taskId?: string } | undefined)?.taskId === taskId,
    );
    expect(matchOnA).toBeDefined();
    expect(matchOnA?.tenantId).toBe(tenantA.id);

    // Tenant isolation: tenant B's connection must NEVER see tenant A's
    // event — not merely "hasn't yet," a structural guarantee (separate
    // Redis channel entirely). A short grace wait, then assert absence.
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    const leakedOnB = connectionB.received.find(
      (envelope) =>
        (envelope.data as { taskId?: string } | undefined)?.taskId === taskId,
    );
    expect(leakedOnB).toBeUndefined();
    expect(
      connectionB.received.every(
        (envelope) => envelope.tenantId === tenantB.id,
      ),
    ).toBe(true);

    connectionA.close();
    connectionB.close();
  }, 30_000);

  it('?prefix= filters on the server, connections of one tenant share one subscriber, and a bad prefix is a 400', async () => {
    const pubsub = app.get(RedisPubSubService);
    const all = openLiveConnection(tokenA);
    const approvalsOnly = openLiveConnection(tokenA, '?prefix=approval.');
    const tasksOnly = openLiveConnection(tokenA, '?prefix=task.');
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    // Three open streams, one shared Redis subscriber for tenant A (tenant B has none open).
    expect(pubsub.sharedSubscriberCount()).toBe(1);

    const agentResponse = await request(app.getHttpServer() as App)
      .post('/agents')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        slug: `sse-agt-${randomUUID().slice(0, 8)}`,
        displayName: 'SSE Prefix Agent',
      })
      .expect(201);
    await request(app.getHttpServer() as App)
      .post('/tasks')
      .set('Authorization', `Bearer ${tokenA}`)
      .send({
        name: 'SSE prefix task',
        assignedAgentId: (agentResponse.body as { id: string }).id,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      })
      .expect(201);

    await waitUntil(
      () =>
        tasksOnly.received.some((e) => e.eventType === 'task.created') &&
        all.received.some((e) => e.eventType === 'task.created'),
      20_000,
    );
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    expect(tasksOnly.received.length).toBeGreaterThan(0);
    expect(
      tasksOnly.received.every((e) => e.eventType.startsWith('task.')),
    ).toBe(true);
    expect(approvalsOnly.received).toEqual([]);

    const bad = await fetch(`${endpoint}/events/live?prefix=bogus.`, {
      headers: { Authorization: `Bearer ${tokenA}` },
    });
    expect(bad.status).toBe(400);
    await bad.body?.cancel();

    all.close();
    approvalsOnly.close();
    tasksOnly.close();
    await waitUntil(() => pubsub.sharedSubscriberCount() === 0, 5_000);
    expect(pubsub.sharedSubscriberCount()).toBe(0);
  }, 40_000);

  it('refuses a tenant user without an audit read role (S24)', async () => {
    const readOnlyToken = await provisionAdminUser(
      tenantA,
      `sse-ro-${randomUUID().slice(0, 8)}`,
      'READ_ONLY',
    );
    const response = await fetch(`${endpoint}/events/live`, {
      headers: { Authorization: `Bearer ${readOnlyToken}` },
    });
    expect(response.status).toBe(403);
    await response.body?.cancel();
  }, 30_000);
});
