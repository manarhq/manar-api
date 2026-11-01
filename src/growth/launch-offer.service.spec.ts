/* eslint-disable @typescript-eslint/require-await -- in-memory fakes of async Prisma calls */
import { describe, expect, it, vi } from 'vitest';
import { LaunchOfferService } from './launch-offer.service';

/** An in-memory control DB whose transaction runs one callback at a time, like the advisory lock. */
function fixture(opts: { slots?: number; stripeFails?: boolean } = {}) {
  const claims: {
    id: string;
    issuer: string;
    subject: string;
    tenantId: string;
    deviceHash: string;
  }[] = [];
  const tenants = new Map<string, unknown>();
  let chain: Promise<unknown> = Promise.resolve();
  const matches = (
    c: (typeof claims)[number],
    w: { OR: Record<string, string>[] },
  ) =>
    w.OR.some((o) =>
      Object.entries(o).every(
        ([k, v]) => (c as Record<string, string>)[k] === v,
      ),
    );
  const txClient = {
    $executeRaw: vi.fn(),
    launchOfferClaim: {
      findFirst: async ({ where }: never) =>
        claims.find((c) => matches(c, where)) ?? null,
      count: async () => claims.length,
      create: async ({ data }: { data: Record<string, string> }) => {
        const row = {
          id: `c${claims.length}`,
          ...data,
        } as (typeof claims)[number];
        claims.push(row);
        return row;
      },
    },
  };
  const control = {
    tenant: {
      findUnique: async ({ where }: { where: { id: string } }) =>
        tenants.get(where.id) ?? null,
    },
    tenantEntitlement: { findUnique: async () => null },
    membership: { findUnique: async () => ({ email: 'a@b.c' }) },
    // serialise: stands in for pg_advisory_xact_lock
    $transaction: (fn: (tx: typeof txClient) => Promise<unknown>) => {
      const run = chain.then(() => fn(txClient));
      chain = run.catch(() => undefined);
      return run;
    },
    launchOfferClaim: {
      update: async () => undefined,
      count: async () => claims.length,
      delete: async ({ where }: { where: { id: string } }) => {
        claims.splice(
          claims.findIndex((c) => c.id === where.id),
          1,
        );
      },
    },
  };
  const create = vi.fn(async () => {
    if (opts.stripeFails) throw new Error('stripe down');
    return { id: 'sub_1' };
  });
  const svc = new LaunchOfferService(
    control as never,
    {
      get: (k: string) =>
        ({
          LAUNCH_OFFER_SLOTS: opts.slots ?? 100,
          LAUNCH_OFFER_ENABLED: 'true',
        })[k],
    } as never,
    {
      configured: true,
      price: () => 'price_x',
      client: () => ({ subscriptions: { create } }),
    } as never,
    { ensureCustomer: async () => 'cus_1' } as never,
    { change: vi.fn() } as never,
    { record: vi.fn() } as never,
  );
  const addTenant = (n: number) =>
    tenants.set(`t${n}`, {
      id: `t${n}`,
      kind: 'PERSONAL',
      status: 'ACTIVE',
      ownerIssuer: 'iss',
      ownerSubject: `u${n}`,
    });
  return { svc, claims, create, addTenant };
}

describe('launch offer', () => {
  it('hands out exactly N slots under parallel registrations', async () => {
    const f = fixture({ slots: 5 });
    for (let i = 0; i < 20; i++) f.addTenant(i);
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        f.svc.claim(`t${i}`, `machine-${i}`),
      ),
    );
    expect(results.filter(Boolean)).toHaveLength(5);
    expect(f.claims).toHaveLength(5);
    expect(f.create).toHaveBeenCalledTimes(5);
    expect((await f.svc.counter()).remaining).toBe(0);
  });

  it('one per person and per device', async () => {
    const f = fixture();
    f.addTenant(1);
    f.addTenant(2);
    expect(await f.svc.claim('t1', 'm1')).toBe(true);
    expect(await f.svc.claim('t1', 'm2')).toBe(false); // same person
    expect(await f.svc.claim('t2', 'm1')).toBe(false); // same device
  });

  it('frees the slot when Stripe fails', async () => {
    const f = fixture({ stripeFails: true });
    f.addTenant(1);
    expect(await f.svc.onDeviceRegistered('t1', 'm1')).toBe(false);
    expect(f.claims).toHaveLength(0);
  });

  it('ignores company workspaces', async () => {
    const f = fixture();
    f.addTenant(1);
    (f.claims as unknown[]).length = 0;
    expect(await f.svc.claim('nope', 'm1')).toBe(false);
  });
});
