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
    contactEmail: {
      deleteMany: async () => (calls.push('contact'), { count: 1 }),
    },
    userDataPreference: { deleteMany: async () => ({ count: 1 }) },
    accountDeletion: {
      findMany: async (a: { where: { status: { in: string[] } } }) =>
        a.where.status.in.includes(row.status) ? [row] : [],
      findUnique: async () => row,
      deleteMany: async (a: { where: { status: { in: string[] } } }) => ({
        count: a.where.status.in.includes(row.status) ? 1 : 0,
      }),
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
    { verified: async () => 'me@acme.io' } as never,
    { get: () => undefined } as never,
    { deleteUserData: async () => void calls.push('data') } as never,
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
      'data',
      'kc:manar:u1',
      'contact',
    ]);
    expect(row.status).toBe('DONE');
  });
  it('keeps the account when the person became the only owner of a company', async () => {
    const { svc, calls, row } = setup({ soleOwner: true });
    expect(await svc.executeDue()).toEqual({ done: 0, failed: 1 });
    expect(calls).toEqual([]);
    // ends the request instead of retrying every hour, and the status says why
    expect(row.status).toBe('REFUSED');
    expect(await svc.status(row.issuer, row.subject)).toEqual({
      scheduled: false,
      refused: 'sole_owner',
    });
    expect(await svc.executeDue()).toEqual({ done: 0, failed: 0 });
  });
  it('lets the person cancel a request that is retrying after a failure', async () => {
    const { svc, row } = setup();
    row.status = 'FAILED';
    await expect(svc.cancel(row.issuer, row.subject)).resolves.toEqual({
      scheduled: false,
    });
  });
  it('finds the realm in an issuer', () => {
    expect(realmOf('https://auth-manar.vax.sh/realms/manar')).toBe('manar');
    expect(realmOf('https://x/y')).toBeNull();
  });
});
