/**
 * Small helpers for the auth e2e suite to drive a *real* local Keycloak
 * instance directly via its Admin REST API — creating realm test users,
 * assigning realm roles, and obtaining real, Keycloak-signed access
 * tokens via the Resource Owner Password Credentials grant. Deliberately
 * separate from `src/keycloak/keycloak-admin.client.ts` (which is scoped
 * to what `TenantProvisioningService` needs, not test setup) even though
 * both talk to the same Admin API.
 *
 * Per the Phase 3 testing requirement: get real tokens from a real local
 * Keycloak wherever feasible, rather than fabricating JWTs, so these
 * helpers are used for every scenario except the two that are
 * structurally impossible to produce any other way (an unrecognized
 * issuer, and a token signed by a key Keycloak never issued) — see
 * test/auth.e2e-spec.ts.
 */

import { Client as PgClient } from 'pg';
import { rolesOf, splitRoles } from '../../src/auth/membership.service';
import { isRoleName, type RoleName } from '../../src/auth/roles';

const baseUrl = process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081';

async function getMasterAdminToken(): Promise<string> {
  const response = await fetch(
    `${baseUrl}/realms/master/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: process.env.KEYCLOAK_ADMIN_CLIENT_ID ?? 'admin-cli',
        username: process.env.KEYCLOAK_ADMIN_USERNAME ?? 'admin',
        password: process.env.KEYCLOAK_ADMIN_PASSWORD ?? 'admin',
      }),
    },
  );
  if (!response.ok) {
    throw new Error(
      `Failed to obtain Keycloak master admin token: HTTP ${response.status}`,
    );
  }
  const body = (await response.json()) as { access_token: string };
  return body.access_token;
}

export async function adminFetch(
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const token = await getMasterAdminToken();
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      Authorization: `Bearer ${token}`,
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
    },
  });
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(
      `Keycloak Admin API ${init.method ?? 'GET'} ${path} failed: HTTP ${response.status}${text ? `: ${text}` : ''}`,
    );
  }
  return response;
}

export async function createRealmUser(
  realm: string,
  input: { username: string; email: string; password: string },
): Promise<string> {
  const createResponse = await adminFetch(
    `/admin/realms/${encodeURIComponent(realm)}/users`,
    {
      method: 'POST',
      body: JSON.stringify({
        username: input.username,
        email: input.email,
        // Recent Keycloak versions (see keycloak/keycloak#36108) reject a
        // direct-grant token request with "Account is not fully set up"
        // for a user with no first/last name, even with an empty
        // requiredActions list and emailVerified: true.
        firstName: 'Test',
        lastName: 'User',
        enabled: true,
        emailVerified: true,
        requiredActions: [],
      }),
    },
  );
  const location = createResponse.headers.get('location');
  const userId = location?.split('/').pop();
  if (!userId) {
    throw new Error(
      `Keycloak did not return a user id for "${input.username}"`,
    );
  }

  await adminFetch(
    `/admin/realms/${encodeURIComponent(realm)}/users/${userId}/reset-password`,
    {
      method: 'PUT',
      body: JSON.stringify({
        type: 'password',
        value: input.password,
        temporary: false,
      }),
    },
  );

  return userId;
}

export async function assignRealmRole(
  realm: string,
  userId: string,
  roleName: string,
): Promise<void> {
  const roleResponse = await adminFetch(
    `/admin/realms/${encodeURIComponent(realm)}/roles/${encodeURIComponent(roleName)}`,
  );
  const role = (await roleResponse.json()) as { id: string; name: string };

  await adminFetch(
    `/admin/realms/${encodeURIComponent(realm)}/users/${userId}/role-mappings/realm`,
    {
      method: 'POST',
      body: JSON.stringify([{ id: role.id, name: role.name }]),
    },
  );
  if (isRoleName(roleName)) await grantMembershipRole(realm, userId, roleName);
}

/**
 * Roles come from `Membership`, never the token, so a realm role alone grants nothing. This does
 * for one user what `memberships:migrate-from-realms` does on upgrade: the realm's tenant gets an
 * ACTIVE Membership (issuer = the tenant's realm issuer) holding every role assigned here. A realm
 * with no tenant row gets nothing.
 */
async function grantMembershipRole(
  realm: string,
  subject: string,
  roleName: RoleName,
): Promise<void> {
  const db = new PgClient({
    connectionString: process.env.CONTROL_DATABASE_URL,
  });
  await db.connect();
  try {
    const { rows: tenants } = await db.query<{ id: string; issuer: string }>(
      `SELECT id, "keycloakIssuerUrl" AS issuer FROM tenants WHERE "keycloakRealm" = $1 AND "keycloakIssuerUrl" IS NOT NULL`,
      [realm],
    );
    const tenant = tenants[0];
    if (!tenant) return;
    const issuer = tenant.issuer.replace(/\/+$/, '');
    const { rows: existing } = await db.query<{
      role: string;
      extraRoles: string[];
    }>(
      `SELECT role::text AS role, "extraRoles"::text[] AS "extraRoles" FROM memberships WHERE issuer = $1 AND subject = $2 AND "tenantId" = $3`,
      [issuer, subject, tenant.id],
    );
    const held = existing[0] ? rolesOf(existing[0]) : [];
    const split = splitRoles([...held, roleName])!;
    await db.query(
      `INSERT INTO memberships (id, issuer, subject, "tenantId", role, "extraRoles", status, "grantedBy", "updatedAt")
       VALUES (gen_random_uuid(), $1, $2, $3, $4::"MembershipRole", $5::"MembershipRole"[], 'ACTIVE', 'e2e:assignRealmRole', now())
       ON CONFLICT (issuer, subject, "tenantId") DO UPDATE
         SET role = EXCLUDED.role, "extraRoles" = EXCLUDED."extraRoles", status = 'ACTIVE', "updatedAt" = now()`,
      [issuer, subject, tenant.id, split.role, split.extraRoles],
    );
  } finally {
    await db.end();
  }
}

/** Resource Owner Password Credentials grant — returns a real signed access token. */
export async function getUserToken(input: {
  realm: string;
  clientId: string;
  clientSecret: string;
  username: string;
  password: string;
}): Promise<string> {
  const response = await fetch(
    `${baseUrl}/realms/${encodeURIComponent(input.realm)}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: input.clientId,
        client_secret: input.clientSecret,
        username: input.username,
        password: input.password,
        scope: 'openid',
      }),
    },
  );
  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(
      `Failed to obtain a user token for "${input.username}" in realm "${input.realm}": HTTP ${response.status}${text ? `: ${text}` : ''}`,
    );
  }
  const body = (await response.json()) as { access_token: string };
  return body.access_token;
}

/** Shortens a realm's access token lifespan so a test can wait for real expiry. */
export async function setRealmAccessTokenLifespan(
  realm: string,
  seconds: number,
): Promise<void> {
  await adminFetch(`/admin/realms/${encodeURIComponent(realm)}`, {
    method: 'PUT',
    body: JSON.stringify({ accessTokenLifespan: seconds }),
  });
}

/**
 * Phase 14 security cleanup 2: reads back a realm client's
 * `redirectUris`/`webOrigins` directly from Keycloak's Admin API — used to
 * confirm `TenantProvisioningService` actually registered `manar-web`'s
 * OIDC callback at provisioning time, not just that the request to do so
 * didn't throw.
 */
export async function getClientRedirectConfig(
  realm: string,
  clientId: string,
): Promise<{ redirectUris: string[]; webOrigins: string[] }> {
  const response = await adminFetch(
    `/admin/realms/${encodeURIComponent(realm)}/clients?clientId=${encodeURIComponent(clientId)}`,
  );
  const clients = (await response.json()) as Array<{
    redirectUris?: string[];
    webOrigins?: string[];
  }>;
  const client = clients[0];
  if (!client) {
    throw new Error(
      `Keycloak client "${clientId}" not found in realm "${realm}"`,
    );
  }
  return {
    redirectUris: client.redirectUris ?? [],
    webOrigins: client.webOrigins ?? [],
  };
}

export async function deleteRealm(realm: string): Promise<void> {
  try {
    await adminFetch(`/admin/realms/${encodeURIComponent(realm)}`, {
      method: 'DELETE',
    });
  } catch {
    // Best-effort cleanup — a realm left behind in local/CI Keycloak after a
    // failed test run doesn't affect other tests (unique realm names).
  }
}

/**
 * ADR-0010: a confidential client-credentials client in the master realm, as manar-fleet uses
 * for /platform/v1. Optionally grants `role` (a master realm role, created if missing) to its
 * service account. Returns the client secret (test-only, never logged).
 */
export async function createPlatformClient(
  clientId: string,
  role: string | null,
): Promise<{ uuid: string; secret: string }> {
  if (role) {
    await adminFetch('/admin/realms/master/roles', {
      method: 'POST',
      body: JSON.stringify({ name: role }),
    }).catch(() => undefined); // already exists
  }
  const created = await adminFetch('/admin/realms/master/clients', {
    method: 'POST',
    body: JSON.stringify({
      clientId,
      protocol: 'openid-connect',
      publicClient: false,
      serviceAccountsEnabled: true,
      standardFlowEnabled: false,
      directAccessGrantsEnabled: false,
    }),
  });
  const uuid = created.headers.get('location')?.split('/').pop();
  if (!uuid)
    throw new Error(`Keycloak did not return a client id for "${clientId}"`);
  const secret = (
    (await (
      await adminFetch(`/admin/realms/master/clients/${uuid}/client-secret`)
    ).json()) as { value: string }
  ).value;
  if (role) {
    const sa = (await (
      await adminFetch(
        `/admin/realms/master/clients/${uuid}/service-account-user`,
      )
    ).json()) as { id: string };
    await assignRealmRole('master', sa.id, role);
  }
  return { uuid, secret };
}

export async function deletePlatformClient(
  uuid: string,
  role?: string,
): Promise<void> {
  await adminFetch(`/admin/realms/master/clients/${uuid}`, {
    method: 'DELETE',
  }).catch(() => undefined);
  if (role)
    await adminFetch(`/admin/realms/master/roles/${encodeURIComponent(role)}`, {
      method: 'DELETE',
    }).catch(() => undefined);
}

export async function getClientCredentialsToken(
  clientId: string,
  secret: string,
): Promise<string> {
  const response = await fetch(
    `${baseUrl}/realms/master/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: secret,
      }),
    },
  );
  if (!response.ok)
    throw new Error(`client_credentials failed: HTTP ${response.status}`);
  return ((await response.json()) as { access_token: string }).access_token;
}
