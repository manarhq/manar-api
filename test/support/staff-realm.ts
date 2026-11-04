import { adminFetch } from './keycloak-test-helpers';
import { STAFF_E2E_REALM } from './staff-env';

const base = process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081';
export const STAFF_E2E_CLIENT_SECRET = 'staff-e2e-client-secret-not-real';
const PASSWORD = 'Staff-e2e-password-1';

const attrMapper = (attr: string, claim: string) => ({
  name: claim,
  protocol: 'openid-connect',
  protocolMapper: 'oidc-usermodel-attribute-mapper',
  config: {
    'user.attribute': attr,
    'claim.name': claim,
    'jsonType.label': 'String',
    'access.token.claim': 'true',
    'id.token.claim': 'false',
    'userinfo.token.claim': 'false',
  },
});

/**
 * A stand-in for vax-staff brokered from Entra: the same claims CORE checks (`idp`, `entra_oid`,
 * `entra_tid`, audience, `acr`), set per user from attributes so tests can vary each one. The
 * production path (fake Entra IdP, passkey step-up) is exercised by DESK's Playwright suite.
 */
export async function createStaffRealm(): Promise<void> {
  await adminFetch('/admin/realms', {
    method: 'POST',
    // Duplicate emails allowed: a test signs in two different people carrying one email claim.
    body: JSON.stringify({
      realm: STAFF_E2E_REALM,
      enabled: true,
      duplicateEmailsAllowed: true,
      loginWithEmailAllowed: false,
    }),
  });
  const profile = (await (
    await adminFetch(`/admin/realms/${STAFF_E2E_REALM}/users/profile`)
  ).json()) as Record<string, unknown>;
  await adminFetch(`/admin/realms/${STAFF_E2E_REALM}/users/profile`, {
    method: 'PUT',
    body: JSON.stringify({ ...profile, unmanagedAttributePolicy: 'ENABLED' }),
  });
  await adminFetch(`/admin/realms/${STAFF_E2E_REALM}/clients`, {
    method: 'POST',
    body: JSON.stringify({
      clientId: 'manar-admin',
      publicClient: false,
      secret: STAFF_E2E_CLIENT_SECRET,
      directAccessGrantsEnabled: true,
      standardFlowEnabled: false,
      defaultClientScopes: ['basic', 'profile', 'email'],
      protocolMappers: [
        attrMapper('test_idp', 'idp'),
        attrMapper('test_oid', 'entra_oid'),
        attrMapper('test_tid', 'entra_tid'),
        attrMapper('test_acr', 'acr'),
        {
          // Direct-grant tokens carry no auth_time: tests stamp it per token (staffToken).
          ...attrMapper('test_auth_time', 'auth_time'),
          config: {
            ...attrMapper('test_auth_time', 'auth_time').config,
            'jsonType.label': 'long',
          },
        },
        {
          name: 'audience',
          protocol: 'openid-connect',
          protocolMapper: 'oidc-audience-mapper',
          config: {
            'included.custom.audience': 'manar-api-staff',
            'access.token.claim': 'true',
          },
        },
      ],
    }),
  });
}

export async function createStaffUser(input: {
  email: string;
  username?: string;
  oid: string;
  tid: string;
  idp?: string;
  acr?: string;
}): Promise<void> {
  const attributes: Record<string, string[]> = {
    test_oid: [input.oid],
    test_tid: [input.tid],
    test_idp: [input.idp ?? 'entra'],
    test_acr: [input.acr ?? 'staff'],
  };
  const res = await adminFetch(`/admin/realms/${STAFF_E2E_REALM}/users`, {
    method: 'POST',
    body: JSON.stringify({
      username: input.username ?? input.email,
      email: input.email,
      firstName: input.email.split('@')[0],
      lastName: 'Staff',
      enabled: true,
      emailVerified: true,
      attributes,
      credentials: [{ type: 'password', value: PASSWORD, temporary: false }],
    }),
  });
  if (!res.headers.get('location')) throw new Error('no user created');
}

export async function staffToken(username: string): Promise<string> {
  // A fresh sign-in time for this token (the passkey step-up checks auth_time <= 300 s).
  const [user] = (await (
    await adminFetch(
      `/admin/realms/${STAFF_E2E_REALM}/users?exact=true&username=${encodeURIComponent(username)}`,
    )
  ).json()) as { id: string; attributes?: Record<string, string[]> }[];
  if (user)
    await adminFetch(`/admin/realms/${STAFF_E2E_REALM}/users/${user.id}`, {
      method: 'PUT',
      body: JSON.stringify({
        ...user,
        attributes: {
          ...user.attributes,
          test_auth_time: [String(Math.floor(Date.now() / 1000))],
        },
      }),
    });
  const res = await fetch(
    `${base}/realms/${STAFF_E2E_REALM}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: 'manar-admin',
        client_secret: STAFF_E2E_CLIENT_SECRET,
        username,
        password: PASSWORD,
        scope: 'openid',
      }),
    },
  );
  if (!res.ok)
    throw new Error(`staff token for ${username}: HTTP ${res.status}`);
  return ((await res.json()) as { access_token: string }).access_token;
}

export async function deleteStaffRealm(): Promise<void> {
  await adminFetch(`/admin/realms/${STAFF_E2E_REALM}`, {
    method: 'DELETE',
  }).catch(() => undefined);
}
