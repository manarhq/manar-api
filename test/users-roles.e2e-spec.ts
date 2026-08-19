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
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
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

/**
 * Phase 14 (Users/Roles/Settings) — `GET /users`, `GET /users/:id`,
 * `POST /users/:id/role-bindings`, `DELETE /users/:id/role-bindings/:role`,
 * run against real local infra (`pnpm infra:up`): real Postgres and a real
 * local Keycloak, exactly like `test/auth.e2e-spec.ts`. The mandatory
 * scenario from this phase's design spec is the privilege-escalation
 * guard (a `SECURITY_ADMIN` cannot grant themselves `TENANT_OWNER`; a
 * `TENANT_OWNER` can grant any role) — see `src/auth/role-privilege.ts`.
 *
 * Every grant/revoke here also verifies the change actually reached
 * Keycloak (not just the local `RoleBinding` row) by pulling a *fresh*
 * token for the affected user after the change and confirming
 * `JwtAuthGuard.syncRoleBindings` — which reconciles every user's
 * `RoleBinding` rows to their token's `realm_access.roles` claim on every
 * request — doesn't revert it. See `UsersService`'s doc comment for why
 * that ordering (Keycloak first) matters.
 */
describe('Users & Roles (e2e)', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenant: ProvisionedTenant;
  let clientSecret: string;

  const OWNER_USERNAME = `owner-${randomUUID().slice(0, 8)}`;
  const SECADMIN_USERNAME = `secadmin-${randomUUID().slice(0, 8)}`;
  const PLAIN_USERNAME = `plain-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  let ownerKeycloakId: string;
  let secAdminKeycloakId: string;
  let plainKeycloakId: string;

  let ownerToken: string;
  let secAdminToken: string;
  let plainToken: string;

  let ownerProfileId: string;
  let secAdminProfileId: string;
  let plainProfileId: string;

  function uniqueSlug(label: string): string {
    return `usrrole-${label}-${randomUUID().slice(0, 8)}`;
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

  async function freshToken(username: string): Promise<string> {
    return getUserToken({
      realm: tenant.keycloakRealm!,
      clientId: tenant.keycloakClientId!,
      clientSecret,
      username,
      password: USER_PASSWORD,
    });
  }

  async function profileIdForKeycloakSubject(
    keycloakSubject: string,
  ): Promise<string> {
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const row = await tenantClient.userProfile.findUniqueOrThrow({
      where: { keycloakSubject },
    });
    return row.id;
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
      name: 'Users Roles Test Tenant',
    });
    if (!tenant.keycloakRealm) {
      throw new Error('Expected provisioned tenant to have a Keycloak realm');
    }

    const secretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId: tenant.id, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    clientSecret = secretRef.reference;

    ownerKeycloakId = await createRealmUser(tenant.keycloakRealm, {
      username: OWNER_USERNAME,
      email: `${OWNER_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(
      tenant.keycloakRealm,
      ownerKeycloakId,
      'TENANT_OWNER',
    );

    secAdminKeycloakId = await createRealmUser(tenant.keycloakRealm, {
      username: SECADMIN_USERNAME,
      email: `${SECADMIN_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(
      tenant.keycloakRealm,
      secAdminKeycloakId,
      'SECURITY_ADMIN',
    );

    plainKeycloakId = await createRealmUser(tenant.keycloakRealm, {
      username: PLAIN_USERNAME,
      email: `${PLAIN_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });

    ownerToken = await freshToken(OWNER_USERNAME);
    secAdminToken = await freshToken(SECADMIN_USERNAME);
    plainToken = await freshToken(PLAIN_USERNAME);

    // Authenticate each once (GET /users has no role gate -- any
    // authenticated tenant user may call it) so JwtAuthGuard
    // find-or-creates every UserProfile row and syncs its initial
    // RoleBinding set before any test references these users by id.
    for (const token of [ownerToken, secAdminToken, plainToken]) {
      await request(app.getHttpServer() as App)
        .get('/users')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
    }

    ownerProfileId = await profileIdForKeycloakSubject(ownerKeycloakId);
    secAdminProfileId = await profileIdForKeycloakSubject(secAdminKeycloakId);
    plainProfileId = await profileIdForKeycloakSubject(plainKeycloakId);
  }, 180_000);

  afterAll(async () => {
    await app.close();
    if (tenant) await cleanupTenant(tenant);
    await control.$disconnect();
  }, 60_000);

  it('1. GET /users lists every user of the tenant with their current RoleBindings', async () => {
    const response = await request(app.getHttpServer() as App)
      .get('/users?limit=100')
      .set('Authorization', `Bearer ${plainToken}`)
      .expect(200);

    const body = response.body as {
      items: { id: string; roles: { role: string }[] }[];
      nextCursor: string | null;
    };
    const ids = body.items.map((item) => item.id);
    expect(ids).toEqual(
      expect.arrayContaining([
        ownerProfileId,
        secAdminProfileId,
        plainProfileId,
      ]),
    );

    const ownerRow = body.items.find((item) => item.id === ownerProfileId)!;
    expect(ownerRow.roles.map((r) => r.role)).toContain('TENANT_OWNER');
  });

  it('2. GET /users/:id returns one user; an unknown id 404s', async () => {
    const response = await request(app.getHttpServer() as App)
      .get(`/users/${secAdminProfileId}`)
      .set('Authorization', `Bearer ${plainToken}`)
      .expect(200);
    const body = response.body as { id: string; roles: { role: string }[] };
    expect(body.id).toBe(secAdminProfileId);
    expect(body.roles.map((r) => r.role)).toContain('SECURITY_ADMIN');

    await request(app.getHttpServer() as App)
      .get(`/users/${randomUUID()}`)
      .set('Authorization', `Bearer ${plainToken}`)
      .expect(404);
  });

  it('3. privilege-escalation guard: a SECURITY_ADMIN cannot grant TENANT_OWNER, including to themselves', async () => {
    const response = await request(app.getHttpServer() as App)
      .post(`/users/${secAdminProfileId}/role-bindings`)
      .set('Authorization', `Bearer ${secAdminToken}`)
      .send({ role: 'TENANT_OWNER' })
      .expect(403);
    expect(JSON.stringify(response.body)).toMatch(/privileged/i);

    // Neither the local RoleBinding nor a real Keycloak role mapping was
    // ever created.
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const binding = await tenantClient.roleBinding.findFirst({
      where: { userId: secAdminProfileId, role: 'TENANT_OWNER' },
    });
    expect(binding).toBeNull();

    const grantedEvents = await tenantClient.auditEvent.findMany({
      where: { eventType: AUDIT_EVENT_TYPES.USER_ROLE_GRANTED },
    });
    expect(
      grantedEvents.some(
        (e) =>
          (e.data as { targetUserId?: string; role?: string })?.targetUserId ===
            secAdminProfileId &&
          (e.data as { role?: string })?.role === 'TENANT_OWNER',
      ),
    ).toBe(false);
  });

  it("4. a TENANT_OWNER can grant any role; the grant reaches Keycloak and survives the affected user's next JwtAuthGuard sync; it is audited", async () => {
    const response = await request(app.getHttpServer() as App)
      .post(`/users/${plainProfileId}/role-bindings`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ role: 'AI_GOVERNANCE_MANAGER' })
      .expect(201);
    const body = response.body as { roles: { role: string }[] };
    expect(body.roles.map((r) => r.role)).toContain('AI_GOVERNANCE_MANAGER');

    // Audited.
    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const grantedEvents = await tenantClient.auditEvent.findMany({
      where: { eventType: AUDIT_EVENT_TYPES.USER_ROLE_GRANTED },
    });
    expect(
      grantedEvents.some(
        (e) =>
          (e.data as { targetUserId?: string })?.targetUserId ===
            plainProfileId &&
          (e.data as { role?: string })?.role === 'AI_GOVERNANCE_MANAGER',
      ),
    ).toBe(true);

    // A FRESH token for the plain user now carries the new role directly
    // from Keycloak -- proving the grant reached Keycloak, not just the
    // local RoleBinding row (which JwtAuthGuard.syncRoleBindings would
    // otherwise silently revert on this user's next authenticated
    // request).
    const refreshedPlainToken = await freshToken(PLAIN_USERNAME);
    const afterSync = await request(app.getHttpServer() as App)
      .get(`/users/${plainProfileId}`)
      .set('Authorization', `Bearer ${refreshedPlainToken}`)
      .expect(200);
    const afterSyncBody = afterSync.body as { roles: { role: string }[] };
    expect(afterSyncBody.roles.map((r) => r.role)).toContain(
      'AI_GOVERNANCE_MANAGER',
    );
  });

  it('5. a SECURITY_ADMIN can grant a role no more privileged than SECURITY_ADMIN itself', async () => {
    const response = await request(app.getHttpServer() as App)
      .post(`/users/${plainProfileId}/role-bindings`)
      .set('Authorization', `Bearer ${secAdminToken}`)
      .send({ role: 'SOC_OPERATOR' })
      .expect(201);
    const body = response.body as { roles: { role: string }[] };
    expect(body.roles.map((r) => r.role)).toContain('SOC_OPERATOR');
  });

  it('6. revoke: a granted role is removed locally, from Keycloak, and does not reappear on the next sync; audited', async () => {
    await request(app.getHttpServer() as App)
      .delete(`/users/${plainProfileId}/role-bindings/AI_GOVERNANCE_MANAGER`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(200);

    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const revokedEvents = await tenantClient.auditEvent.findMany({
      where: { eventType: AUDIT_EVENT_TYPES.USER_ROLE_REVOKED },
    });
    expect(
      revokedEvents.some(
        (e) =>
          (e.data as { targetUserId?: string })?.targetUserId ===
            plainProfileId &&
          (e.data as { role?: string })?.role === 'AI_GOVERNANCE_MANAGER',
      ),
    ).toBe(true);

    const refreshedPlainToken = await freshToken(PLAIN_USERNAME);
    const afterSync = await request(app.getHttpServer() as App)
      .get(`/users/${plainProfileId}`)
      .set('Authorization', `Bearer ${refreshedPlainToken}`)
      .expect(200);
    const afterSyncBody = afterSync.body as { roles: { role: string }[] };
    const roleNames = afterSyncBody.roles.map((r) => r.role);
    expect(roleNames).not.toContain('AI_GOVERNANCE_MANAGER');
    // The unrelated SOC_OPERATOR grant from scenario 5 is untouched.
    expect(roleNames).toContain('SOC_OPERATOR');
  });

  it('7. revoking a role the user does not hold is an idempotent no-op success', async () => {
    await request(app.getHttpServer() as App)
      .delete(`/users/${plainProfileId}/role-bindings/AUDITOR`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(200);
  });

  it('8. a caller with neither TENANT_OWNER nor SECURITY_ADMIN cannot grant or revoke roles at all', async () => {
    await request(app.getHttpServer() as App)
      .post(`/users/${plainProfileId}/role-bindings`)
      .set('Authorization', `Bearer ${plainToken}`)
      .send({ role: 'READ_ONLY' })
      .expect(403);

    await request(app.getHttpServer() as App)
      .delete(`/users/${plainProfileId}/role-bindings/SOC_OPERATOR`)
      .set('Authorization', `Bearer ${plainToken}`)
      .expect(403);
  });

  it('9. revoke privilege-escalation guard: a SECURITY_ADMIN cannot revoke TENANT_OWNER from anyone, including the actual owner', async () => {
    const response = await request(app.getHttpServer() as App)
      .delete(`/users/${ownerProfileId}/role-bindings/TENANT_OWNER`)
      .set('Authorization', `Bearer ${secAdminToken}`)
      .expect(403);
    expect(JSON.stringify(response.body)).toMatch(/privileged/i);

    // The owner's TENANT_OWNER role was never actually touched -- neither
    // the local RoleBinding nor the real Keycloak role mapping.
    const check = await request(app.getHttpServer() as App)
      .get(`/users/${ownerProfileId}`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .expect(200);
    const checkBody = check.body as { roles: { role: string }[] };
    expect(checkBody.roles.map((r) => r.role)).toContain('TENANT_OWNER');

    const tenantClient = await tenantDatabaseManager.getClient(tenant.id);
    const revokedEvents = await tenantClient.auditEvent.findMany({
      where: { eventType: AUDIT_EVENT_TYPES.USER_ROLE_REVOKED },
    });
    expect(
      revokedEvents.some(
        (e) =>
          (e.data as { targetUserId?: string })?.targetUserId ===
            ownerProfileId &&
          (e.data as { role?: string })?.role === 'TENANT_OWNER',
      ),
    ).toBe(false);
  });
});
