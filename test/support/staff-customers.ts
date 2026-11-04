import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { ControlPrismaService } from '../../src/database/control-prisma.service';
import { TenantDatabaseManager } from '../../src/database/tenant-database-manager.service';
import { normalizeEmail } from '../../src/staff/restrictions/fingerprints';
import { adminFetch } from './keycloak-test-helpers';
import {
  CUSTOMER_E2E_ISSUER,
  CUSTOMER_E2E_REALM,
  STAFF_E2E_SUFFIX,
} from './staff-env';

const base = process.env.KEYCLOAK_BASE_URL ?? 'http://localhost:8081';
const SECRET = 'customer-e2e-client-secret-not-real';
const PASSWORD = 'Customer-e2e-password-1';

/** A throwaway customer realm with the API's client (direct grant for tests). */
export async function createCustomerRealm(): Promise<void> {
  await adminFetch('/admin/realms', {
    method: 'POST',
    body: JSON.stringify({
      realm: CUSTOMER_E2E_REALM,
      enabled: true,
      eventsEnabled: true,
      enabledEventTypes: ['LOGIN', 'LOGIN_ERROR'],
    }),
  });
  await adminFetch(`/admin/realms/${CUSTOMER_E2E_REALM}/clients`, {
    method: 'POST',
    body: JSON.stringify({
      clientId: process.env.KEYCLOAK_CLIENT_ID ?? 'manar-api',
      publicClient: false,
      secret: SECRET,
      directAccessGrantsEnabled: true,
      standardFlowEnabled: false,
      defaultClientScopes: ['basic', 'profile', 'email'],
    }),
  });
}

export async function deleteCustomerRealm(): Promise<void> {
  await adminFetch(`/admin/realms/${CUSTOMER_E2E_REALM}`, {
    method: 'DELETE',
  }).catch(() => undefined);
}

export interface Customer {
  accountId: string;
  subject: string;
  email: string;
  username: string;
  tenantId: string;
  token: () => Promise<string>;
}

/**
 * A signed-up person: a Keycloak user, a PERSONAL workspace (real tenant database), an owner
 * membership and an `accounts` row, as sign-up leaves them.
 */
export async function seedCustomer(
  app: INestApplication,
  name: string,
  opts: {
    email?: string;
    plan?: 'free' | 'pro';
    stripeCustomerId?: string;
  } = {},
): Promise<Customer> {
  const control = app.get(ControlPrismaService);
  const manager = app.get(TenantDatabaseManager);
  const username = `${name}-${STAFF_E2E_SUFFIX}`;
  const email = opts.email ?? `${username}@example.test`;
  const res = await adminFetch(`/admin/realms/${CUSTOMER_E2E_REALM}/users`, {
    method: 'POST',
    body: JSON.stringify({
      username,
      email,
      firstName: name,
      lastName: 'Customer',
      enabled: true,
      emailVerified: true,
      credentials: [{ type: 'password', value: PASSWORD, temporary: false }],
    }),
  });
  const subject = res.headers.get('location')!.split('/').pop()!;
  const tenant = await manager.provisionTenant({
    slug: `p-${name}-${randomUUID().slice(0, 6)}`,
    name: `${name} (personal)`,
    kind: 'PERSONAL',
    ownerIssuer: CUSTOMER_E2E_ISSUER,
    ownerSubject: subject,
  });
  await control.membership.create({
    data: {
      issuer: CUSTOMER_E2E_ISSUER,
      subject,
      tenantId: tenant.id,
      role: 'TENANT_OWNER',
      status: 'ACTIVE',
      email,
      displayName: `${name} Customer`,
    },
  });
  await control.tenantEntitlement.upsert({
    where: { tenantId: tenant.id },
    create: {
      tenantId: tenant.id,
      plan: opts.plan ?? 'free',
      stripeCustomerId: opts.stripeCustomerId,
    },
    update: {
      plan: opts.plan ?? 'free',
      stripeCustomerId: opts.stripeCustomerId,
    },
  });
  const account = await control.account.create({
    data: {
      issuer: CUSTOMER_E2E_ISSUER,
      subject,
      displayName: `${name} Customer`,
      normalizedEmail: normalizeEmail(email),
      emailVerified: true,
      idp: 'email',
    },
  });
  return {
    accountId: account.id,
    subject,
    email,
    username,
    tenantId: tenant.id,
    token: () => customerToken(username),
  };
}

export async function customerToken(username: string): Promise<string> {
  const res = await fetch(
    `${base}/realms/${CUSTOMER_E2E_REALM}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: process.env.KEYCLOAK_CLIENT_ID ?? 'manar-api',
        client_secret: SECRET,
        username,
        password: PASSWORD,
        scope: 'openid',
      }),
    },
  );
  if (!res.ok)
    throw new Error(`customer token for ${username}: HTTP ${res.status}`);
  return ((await res.json()) as { access_token: string }).access_token;
}

/** Tenant databases created by a spec, to drop in afterAll. */
export async function dropCustomers(
  app: INestApplication,
  customers: { tenantId: string }[],
) {
  const manager = app.get(TenantDatabaseManager);
  for (const c of customers)
    await manager.deprovisionTenant(c.tenantId).catch(() => undefined);
}
