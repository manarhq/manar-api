import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { Test, TestingModule } from '@nestjs/testing';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { generateKeyPair, SignJWT } from 'jose';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import type { AuthContext } from '../src/auth/auth-context';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { KeycloakModule } from '../src/keycloak/keycloak.module';
import { TenantProvisioningService } from '../src/keycloak/tenant-provisioning.service';
import { ProtectedTestModule } from './fixtures/protected-test.module';
import {
  assignRealmRole,
  createRealmUser,
  deleteRealm,
  getClientRedirectConfig,
  getUserToken,
  setRealmAccessTokenLifespan,
} from './support/keycloak-test-helpers';

/**
 * Mandatory Phase 3 auth scenarios (design spec's "Testing" section), run
 * against a real HTTP server, real local Postgres (`pnpm infra:up`), and a
 * real local Keycloak instance — never a mocked JWKS endpoint or a fully
 * mocked database. Tokens come from real Keycloak Resource Owner Password
 * Credentials grants wherever a real flow is possible; the two scenarios
 * that are structurally impossible to produce any other way (an
 * unrecognized issuer, and a signature from a key Keycloak never issued)
 * fabricate a JWT with `jose`'s `SignJWT` — see each test's comment.
 */
describe('Auth (e2e) — JwtAuthGuard / RolesGuard', () => {
  let app: NestFastifyApplication;
  let control: ControlPrismaService;
  let tenantDatabaseManager: TenantDatabaseManager;
  let provisioning: TenantProvisioningService;

  type ProvisionedTenant = Awaited<
    ReturnType<TenantProvisioningService['provisionTenant']>
  >;
  let tenantA: ProvisionedTenant;
  let tenantB: ProvisionedTenant;
  let clientSecretA: string;

  const adminUserAId = { current: '' };
  const plainUserAId = { current: '' };
  const ADMIN_USERNAME = `admin-${randomUUID().slice(0, 8)}`;
  const PLAIN_USERNAME = `plain-${randomUUID().slice(0, 8)}`;
  const USER_PASSWORD = 'Passw0rd!Test';

  function uniqueSlug(label: string): string {
    return `auth-${label}-${randomUUID().slice(0, 8)}`;
  }

  async function clientSecretFor(tenantId: string): Promise<string> {
    const secretRef = await control.secretReference.findFirstOrThrow({
      where: { tenantId, kind: 'KEYCLOAK_CLIENT_SECRET' },
    });
    return secretRef.reference;
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

  async function cleanupTenant(tenant: ProvisionedTenant): Promise<void> {
    if (tenant.keycloakRealm) {
      await deleteRealm(tenant.keycloakRealm);
    }
    if (tenant.databaseBinding?.databaseName) {
      await dropRealDatabase(tenant.databaseBinding.databaseName);
    }
    // TenantDatabaseBinding FKs to SecretReference — delete it first.
    await control.tenantDatabaseBinding.deleteMany({
      where: { tenantId: tenant.id },
    });
    await control.secretReference.deleteMany({
      where: { tenantId: tenant.id },
    });
    await control.tenant.deleteMany({ where: { id: tenant.id } });
  }

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      // AppModule imports KeycloakModule itself since Phase 14 (UsersService
      // needs KeycloakAdminClient at runtime -- see keycloak.module.ts's doc
      // comment), but TenantProvisioningService remains something only the
      // CLI and tests actually call; this test still imports KeycloakModule
      // explicitly (redundant with AppModule's own import, but harmless --
      // Nest dedupes module imports) to make that dependency obvious at this
      // call site, the same way the CLI's CliModule does, purely to
      // provision real tenant fixtures.
      imports: [AppModule, KeycloakModule, ProtectedTestModule],
    }).compile();

    app = moduleFixture.createNestApplication<NestFastifyApplication>(
      new FastifyAdapter(),
    );
    await app.init();
    await app.getHttpAdapter().getInstance().ready();

    control = app.get(ControlPrismaService);
    tenantDatabaseManager = app.get(TenantDatabaseManager);
    provisioning = app.get(TenantProvisioningService);

    tenantA = await provisioning.provisionTenant({
      slug: uniqueSlug('a'),
      name: 'Auth Tenant A',
    });
    tenantB = await provisioning.provisionTenant({
      slug: uniqueSlug('b'),
      name: 'Auth Tenant B',
    });

    if (!tenantA.keycloakRealm || !tenantB.keycloakRealm) {
      throw new Error('Expected provisioned tenants to have a Keycloak realm');
    }

    clientSecretA = await clientSecretFor(tenantA.id);
    // Asserts tenant B was provisioned with its own real client secret too
    // (not reused by identity from tenant A's) — the value itself isn't
    // needed by any scenario below.
    expect(await clientSecretFor(tenantB.id)).not.toBe(clientSecretA);

    // A user with SECURITY_ADMIN in tenant A's realm...
    adminUserAId.current = await createRealmUser(tenantA.keycloakRealm, {
      username: ADMIN_USERNAME,
      email: `${ADMIN_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(
      tenantA.keycloakRealm,
      adminUserAId.current,
      'SECURITY_ADMIN',
    );

    // ...and a user with no roles at all, for the RolesGuard-denies test.
    plainUserAId.current = await createRealmUser(tenantA.keycloakRealm, {
      username: PLAIN_USERNAME,
      email: `${PLAIN_USERNAME}@example.test`,
      password: USER_PASSWORD,
    });
  }, 120_000);

  afterAll(async () => {
    await app.close();
    if (tenantA) await cleanupTenant(tenantA);
    if (tenantB) await cleanupTenant(tenantB);
    await control.$disconnect();
  }, 60_000);

  it('8. concurrent first requests from a new user all succeed and bind each role once', async () => {
    // Load test finding (9 Oct): two simultaneous first requests both saw
    // no RoleBinding and both inserted it; the loser hit the (userId, role)
    // unique constraint and the request returned 500.
    const username = `first-${randomUUID().slice(0, 8)}`;
    const userId = await createRealmUser(tenantA.keycloakRealm!, {
      username,
      email: `${username}@example.test`,
      password: USER_PASSWORD,
    });
    await assignRealmRole(tenantA.keycloakRealm!, userId, 'SECURITY_ADMIN');
    const token = await getUserToken({
      realm: tenantA.keycloakRealm!,
      clientId: tenantA.keycloakClientId!,
      clientSecret: clientSecretA,
      username,
      password: USER_PASSWORD,
    });

    const statuses = await Promise.all(
      Array.from({ length: 20 }, () =>
        request(app.getHttpServer() as App)
          .get('/__test-protected/security-admin-only')
          .set('Authorization', `Bearer ${token}`)
          .then((r) => r.status),
      ),
    );

    expect(statuses).toEqual(Array.from({ length: 20 }, () => 200));
    const tenantAClient = await tenantDatabaseManager.getClient(tenantA.id);
    const bindings = await tenantAClient.roleBinding.findMany({
      where: { user: { keycloakSubject: userId } },
    });
    expect(bindings.map((b) => b.role)).toEqual(['SECURITY_ADMIN']);
  }, 30_000);

  it('1. a valid token from a known tenant realm succeeds with the correct AuthContext', async () => {
    const token = await getUserToken({
      realm: tenantA.keycloakRealm!,
      clientId: tenantA.keycloakClientId!,
      clientSecret: clientSecretA,
      username: ADMIN_USERNAME,
      password: USER_PASSWORD,
    });

    const response = await request(app.getHttpServer() as App)
      .get('/__test-protected/any-authenticated-user')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    const body = response.body as AuthContext;

    expect(body.tenant.id).toBe(tenantA.id);
    expect(body.user.keycloakSubject).toBe(adminUserAId.current);
    expect(body.roles).toContain('SECURITY_ADMIN');

    // Also asserts the guard's find-or-create actually persisted a
    // UserProfile in tenant A's own isolated database.
    const tenantAClient = await tenantDatabaseManager.getClient(tenantA.id);
    const profile = await tenantAClient.userProfile.findUnique({
      where: { keycloakSubject: adminUserAId.current },
    });
    expect(profile).not.toBeNull();

    // The role-gated endpoint must also succeed for this SECURITY_ADMIN user.
    await request(app.getHttpServer() as App)
      .get('/__test-protected/security-admin-only')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  }, 30_000);

  it('2. a token with an unrecognized issuer, or an attacker-controlled signing key, is rejected', async () => {
    const { privateKey } = await generateKeyPair('RS256');

    // 2a. iss points nowhere this deployment ever provisioned — must be
    // rejected by the control-DB allow-list lookup before any JWKS fetch
    // is even attempted. There is no way to produce this scenario against
    // a real Keycloak (by definition, no realm is provisioned for it), so
    // this token is necessarily fabricated.
    const unknownIssuerToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer('http://localhost:8081/realms/does-not-exist-in-control-db')
      .setSubject('attacker')
      .setExpirationTime('5m')
      .sign(privateKey);

    await request(app.getHttpServer() as App)
      .get('/__test-protected/any-authenticated-user')
      .set('Authorization', `Bearer ${unknownIssuerToken}`)
      .expect(401);

    // 2b. iss correctly points at tenant A's real, provisioned realm, but
    // the token is signed with a key Keycloak never issued (an attacker
    // who knows a real issuer URL but not the realm's private key). The
    // guard must fetch tenant A's REAL JWKS from the real Keycloak and
    // fail signature verification against it — there is no way to make
    // Keycloak itself sign with the wrong key, so this forged token is
    // the only way to exercise this exact failure path.
    const wrongKeyToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(tenantA.keycloakIssuerUrl!)
      .setSubject('attacker')
      .setExpirationTime('5m')
      .sign(privateKey);

    await request(app.getHttpServer() as App)
      .get('/__test-protected/any-authenticated-user')
      .set('Authorization', `Bearer ${wrongKeyToken}`)
      .expect(401);
  }, 20_000);

  it('3. a token valid for tenant A cannot be used to act as tenant B', async () => {
    const tokenA = await getUserToken({
      realm: tenantA.keycloakRealm!,
      clientId: tenantA.keycloakClientId!,
      clientSecret: clientSecretA,
      username: ADMIN_USERNAME,
      password: USER_PASSWORD,
    });

    const response = await request(app.getHttpServer() as App)
      .get('/__test-protected/any-authenticated-user')
      .set('Authorization', `Bearer ${tokenA}`)
      .expect(200);
    const body = response.body as AuthContext;

    // The issuer embedded in the (verified) token is the sole source of
    // tenant identity — it can only ever resolve to tenant A, never B.
    expect(body.tenant.id).toBe(tenantA.id);
    expect(body.tenant.id).not.toBe(tenantB.id);

    // And tenant B's own isolated database was never touched: no
    // UserProfile exists there for this Keycloak subject.
    const tenantBClient = await tenantDatabaseManager.getClient(tenantB.id);
    const profileInB = await tenantBClient.userProfile.findUnique({
      where: { keycloakSubject: adminUserAId.current },
    });
    expect(profileInB).toBeNull();
  }, 20_000);

  it('4. an expired token is rejected', async () => {
    await setRealmAccessTokenLifespan(tenantA.keycloakRealm!, 1);
    try {
      const shortLivedToken = await getUserToken({
        realm: tenantA.keycloakRealm!,
        clientId: tenantA.keycloakClientId!,
        clientSecret: clientSecretA,
        username: ADMIN_USERNAME,
        password: USER_PASSWORD,
      });

      await new Promise((resolve) => setTimeout(resolve, 2500));

      await request(app.getHttpServer() as App)
        .get('/__test-protected/any-authenticated-user')
        .set('Authorization', `Bearer ${shortLivedToken}`)
        .expect(401);
    } finally {
      await setRealmAccessTokenLifespan(tenantA.keycloakRealm!, 300);
    }
  }, 20_000);

  it('5. a missing or malformed Authorization header is rejected with 401 and no stack trace leaked', async () => {
    const missing = await request(app.getHttpServer() as App)
      .get('/__test-protected/any-authenticated-user')
      .expect(401);
    const missingBody = missing.body as { stack?: unknown };
    expect(JSON.stringify(missingBody)).not.toMatch(/at .*\(.*:\d+:\d+\)/);
    expect(missingBody.stack).toBeUndefined();

    const malformed = await request(app.getHttpServer() as App)
      .get('/__test-protected/any-authenticated-user')
      .set('Authorization', 'NotBearer some-garbage-value')
      .expect(401);
    const malformedBody = malformed.body as { stack?: unknown };
    expect(JSON.stringify(malformedBody)).not.toMatch(/at .*\(.*:\d+:\d+\)/);
    expect(malformedBody.stack).toBeUndefined();
    expect(JSON.stringify(malformedBody)).not.toContain('node_modules');
  }, 20_000);

  it('6. RolesGuard denies a user lacking the required role', async () => {
    const token = await getUserToken({
      realm: tenantA.keycloakRealm!,
      clientId: tenantA.keycloakClientId!,
      clientSecret: clientSecretA,
      username: PLAIN_USERNAME,
      password: USER_PASSWORD,
    });

    // The plain user is a genuinely authenticated tenant-A user — the
    // unguarded-by-role endpoint must still accept them.
    await request(app.getHttpServer() as App)
      .get('/__test-protected/any-authenticated-user')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    // But the SECURITY_ADMIN-gated endpoint must reject them.
    await request(app.getHttpServer() as App)
      .get('/__test-protected/security-admin-only')
      .set('Authorization', `Bearer ${token}`)
      .expect(403);
  }, 20_000);

  it("7. Phase 14 security cleanup 2: provisioning registers manar-web's OIDC redirect URI/web origin on the confidential client", async () => {
    // TenantProvisioningService.provisionTenant already ran for tenantA in
    // beforeAll -- this confirms it actually registered manar-web's static
    // callback URL on the confidential client at creation time (Phase 14
    // security cleanup 2), not just that client creation itself succeeded.
    // Closes the gap manar-web/lib/auth/keycloak-admin.ts's
    // `ensureRedirectUriRegistered` used to fill in lazily, on the first
    // login attempt, using standing Keycloak admin credentials manar-web
    // no longer needs to hold as a result.
    const manarWebBaseUrl =
      process.env.MANAR_WEB_BASE_URL ?? 'http://localhost:3100';
    const expectedRedirectUri = new URL(
      '/api/auth/callback',
      manarWebBaseUrl,
    ).toString();
    const expectedWebOrigin = new URL(manarWebBaseUrl).origin;

    const clientConfig = await getClientRedirectConfig(
      tenantA.keycloakRealm!,
      tenantA.keycloakClientId!,
    );
    expect(clientConfig.redirectUris).toContain(expectedRedirectUri);
    expect(clientConfig.webOrigins).toContain(expectedWebOrigin);
  }, 20_000);
});
