/* eslint-disable @typescript-eslint/require-await -- in-memory fakes of async Prisma calls */
import { describe, expect, it, vi } from 'vitest';
import { AccountService, realmOf } from './account.service';

function setup(
  opts: { soleOwner?: boolean; deployment?: 'hosted' | 'customer' } = {},
) {
  const calls: string[] = [];
  const hostUpdates: { where: unknown; data: Record<string, unknown> }[] = [];
  const mails: string[] = [];
  const audits: string[] = [];
  const row = {
    id: 'd1',
    issuer: 'https://kc/realms/manar',
    subject: 'u1',
    status: 'SCHEDULED',
    executeAfter: new Date(0),
  };
  const control = {
    deletedWorkspace: {
      upsert: async (a: { where: { slug: string } }) =>
        void calls.push(`tombstone:${a.where.slug}`),
    },
    membership: {
      findMany: async (a: { where: Record<string, unknown> }) =>
        opts.soleOwner
          ? [{ tenantId: 'co', role: 'TENANT_OWNER', extraRoles: [] }]
          : 'subject' in a.where
            ? // the deleted person's company memberships
              [
                {
                  tenantId: 'co',
                  role: 'DEVELOPER',
                  extraRoles: [],
                  tenant: { id: 'co', kind: 'COMPANY', status: 'ACTIVE' },
                },
              ]
            : // that company's owners and admins
              [{ issuer: 'https://kc/realms/manar', subject: 'boss' }],
      count: async () => 0,
      deleteMany: async () => (calls.push('memberships'), { count: 1 }),
    },
    tenant: {
      findMany: async () => [
        { id: 'p1', slug: 'p-1', kind: 'PERSONAL', status: 'ACTIVE' },
      ],
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
      getClient: async (id: string) => ({
        host: {
          updateMany: async (a: {
            where: unknown;
            data: Record<string, unknown>;
          }) => {
            hostUpdates.push(a);
            calls.push(id === 'co' ? 'unassign' : 'remove');
            return { count: 2 };
          },
          findMany: async () => [{ id: 'h-co-1' }],
        },
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
    {
      send: async (m: { to: string }) => (mails.push(m.to), true),
    } as never,
    {
      verified: async (_i: string, s: string) =>
        s === 'boss' ? 'boss@acme.io' : 'me@acme.io',
    } as never,
    {
      get: (k: string) =>
        k === 'MANAR_DEPLOYMENT' ? (opts.deployment ?? 'hosted') : undefined,
    } as never,
    { deleteUserData: async () => void calls.push('data') } as never,
    {
      record: async (tenantId: string, type: string) =>
        void audits.push(`${tenantId}:${type}`),
    } as never,
  );
  return { svc, calls, row, hostUpdates, mails, audits };
}

describe('account deletion', () => {
  it('runs Stripe, devices, workspace, memberships, Keycloak in that order', async () => {
    const { svc, calls, row } = setup();
    expect(await svc.executeDue()).toEqual({ done: 1, failed: 0 });
    expect(calls).toEqual([
      'stripe:cancel',
      'stripe:del',
      'tombstone:p-1',
      'remove',
      'workspace',
      'unassign',
      'memberships',
      'data',
      'kc:manar:u1',
      'contact',
    ]);
    expect(row.status).toBe('DONE');
  });
  it('marks personal devices REMOVED (not REVOKED) and leaves a tombstone, so the devices are told to clean up', async () => {
    const { svc, hostUpdates } = setup();
    await svc.executeDue();
    expect(hostUpdates[0]!.data).toMatchObject({
      status: 'REMOVED',
      removedReason: 'account_deleted',
    });
    expect(hostUpdates[0]!.data.removedAt).toBeInstanceOf(Date);
  });
  it('leaves the company devices protected but unassigned, and tells the company admins', async () => {
    const { svc, hostUpdates, mails, audits } = setup();
    await svc.executeDue();
    const unassign = hostUpdates[1]!;
    expect(unassign.where).toMatchObject({ ownerSubject: 'u1' });
    expect(unassign.data).toMatchObject({ ownerSubject: null });
    expect(unassign.data.unassignedAt).toBeInstanceOf(Date);
    expect(unassign.data).not.toHaveProperty('status');
    expect(audits).toEqual(['co:member.account_deleted', 'co:host.unassigned']);
    expect(mails).toContain('boss@acme.io');
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
  it('never deletes the sign-in account from a customer-hosted realm', async () => {
    const { svc, calls } = setup({ deployment: 'customer' });
    expect(await svc.executeDue()).toEqual({ done: 1, failed: 0 });
    expect(calls.some((c) => c.startsWith('kc:'))).toBe(false);
  });
  it('lets the person cancel a request that is retrying after a failure', async () => {
    const { svc, row } = setup();
    row.status = 'FAILED';
    await expect(svc.cancel(row.issuer, row.subject)).resolves.toEqual({
      scheduled: false,
    });
  });
  it('finds the realm in an issuer', () => {
    expect(realmOf('https://auth-manar.fixio.ae/realms/manar')).toBe('manar');
    expect(realmOf('https://x/y')).toBeNull();
  });
});
