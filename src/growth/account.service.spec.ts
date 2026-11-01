/* eslint-disable @typescript-eslint/require-await -- in-memory fakes of async Prisma calls */
import { describe, expect, it, vi } from 'vitest';
import { AccountService, realmOf } from './account.service';

function setup(opts: { soleOwner?: boolean } = {}) {
  const calls: string[] = [];
  const row = {
    id: 'd1',
    issuer: 'https://kc/realms/manar',
    subject: 'u1',
    status: 'SCHEDULED',
    executeAfter: new Date(0),
  };
  const control = {
    membership: {
      findMany: async () =>
        opts.soleOwner
          ? [{ tenantId: 'co', role: 'TENANT_OWNER', extraRoles: [] }]
          : [],
      count: async () => 0,
      deleteMany: async () => (calls.push('memberships'), { count: 1 }),
    },
    tenant: {
      findMany: async () => [{ id: 'p1', kind: 'PERSONAL', status: 'ACTIVE' }],
    },
    tenantEntitlement: {
      findUnique: async () => ({
        stripeSubscriptionId: 'sub_1',
        stripeCustomerId: 'cus_1',
      }),
    },
    accountDeletion: {
      findMany: async () => [row],
      updateMany: async () => ({ count: 1 }),
      update: vi.fn(
        async (a: { data: { status: string } }) => (row.status = a.data.status),
      ),
    },
  };
  const svc = new AccountService(
    control as never,
    {
      getClient: async () => ({
        host: { updateMany: async () => (calls.push('revoke'), { count: 2 }) },
      }),
    } as never,
    { deleteOwnedWorkspace: async () => void calls.push('workspace') } as never,
    {
      deleteUser: async (r: string, u: string) =>
        void calls.push(`kc:${r}:${u}`),
    } as never,
    {
      configured: true,
      client: () => ({
        subscriptions: { cancel: async () => void calls.push('stripe:cancel') },
        customers: { del: async () => void calls.push('stripe:del') },
      }),
    } as never,
    { send: async () => true } as never,
    { get: () => undefined } as never,
  );
  return { svc, calls, row };
}

describe('account deletion', () => {
  it('runs Stripe, devices, workspace, memberships, Keycloak in that order', async () => {
    const { svc, calls, row } = setup();
    expect(await svc.executeDue()).toEqual({ done: 1, failed: 0 });
    expect(calls).toEqual([
      'stripe:cancel',
      'stripe:del',
      'revoke',
      'workspace',
      'memberships',
      'kc:manar:u1',
    ]);
    expect(row.status).toBe('DONE');
  });
  it('keeps the account when the person became the only owner of a company', async () => {
    const { svc, calls, row } = setup({ soleOwner: true });
    expect(await svc.executeDue()).toEqual({ done: 0, failed: 1 });
    expect(calls).toEqual([]);
    expect(row.status).toBe('FAILED');
  });
  it('finds the realm in an issuer', () => {
    expect(realmOf('https://auth-manar.vax.sh/realms/manar')).toBe('manar');
    expect(realmOf('https://x/y')).toBeNull();
  });
});
