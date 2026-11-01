/* eslint-disable @typescript-eslint/require-await -- in-memory fakes of async Prisma calls */
import { describe, expect, it, vi } from 'vitest';
import { LaunchOfferService } from './launch-offer.service';

/** An in-memory control DB whose transaction runs one callback at a time, like the advisory lock. */
function fixture(
  opts: {
    slots?: number;
    stripeFails?: boolean;
    idp?: string | null;
    email?: string | null;
  } = {},
) {
  const claims: {
    claimedAt?: Date;
    emailDomain?: string;
    ipHash?: string;

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
        ([k, v]) => (c as unknown as Record<string, string>)[k] === v,
      ),
    );
  const txClient = {
    $executeRaw: vi.fn(),
    launchOfferClaim: {
      findFirst: async ({ where }: never) =>
        claims.find((c) => matches(c, where)) ?? null,
      count: async (a?: { where?: Record<string, unknown> }) =>
        claims.filter((c) =>
          Object.entries(a?.where ?? {}).every(([k, v]) =>
            k === 'claimedAt' ? true : (c as Record<string, unknown>)[k] === v,
          ),
        ).length,
      create: async ({ data }: { data: Record<string, string> }) => {
        const row = {
          id: `c${claims.length}`,
          claimedAt: new Date(),
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
  const create = vi.fn(async (...[,]: [Record<string, unknown>?]) => {
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
      client: () => ({
        subscriptions: { create, list: async () => ({ data: [] }) },
      }),
    } as never,
    { ensureCustomer: async () => 'cus_1' } as never,
    { change: vi.fn() } as never,
    { record: vi.fn() } as never,
    {
      idpOf: async () => ('idp' in opts ? opts.idp : 'github'),
      verified: async () => opts.email ?? null,
    } as never,
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
        f.svc.claim(`t${i}`, { machineId: `machine-${i}` }),
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
    expect(await f.svc.claim('t1', { machineId: 'm1' })).toBe(true);
    expect(await f.svc.claim('t1', { machineId: 'm2' })).toBe(false); // same person
    expect(await f.svc.claim('t2', { machineId: 'm1' })).toBe(false); // same device
  });

  it('frees the slot when Stripe fails', async () => {
    const f = fixture({ stripeFails: true });
    f.addTenant(1);
    expect(await f.svc.onDeviceRegistered('t1', { machineId: 'm1' })).toBe(
      false,
    );
    expect(f.claims).toHaveLength(0);
  });

  it('ignores company workspaces', async () => {
    const f = fixture();
    f.addTenant(1);
    (f.claims as unknown[]).length = 0;
    expect(await f.svc.claim('nope', { machineId: 'm1' })).toBe(false);
  });

  it('needs a Microsoft or GitHub sign-in, or a verified non-disposable email', async () => {
    const link = (email: string | null) => fixture({ idp: null, email });
    for (const [email, ok] of [
      [null, false],
      ['x@mailinator.com', false],
      ['x@acme.io', true],
    ] as const) {
      const f = link(email);
      f.addTenant(1);
      expect(await f.svc.claim('t1', { machineId: 'm' }), String(email)).toBe(
        ok,
      );
    }
    const ms = fixture({ idp: 'microsoft' });
    ms.addTenant(1);
    expect(await ms.svc.claim('t1', { machineId: 'm' })).toBe(true);
  });

  it('caps claims per email domain (not consumer domains) and per address, and counts the TPM key', async () => {
    const f = fixture({ idp: null, email: 'p@acme.io' });
    for (let i = 0; i < 5; i++) f.addTenant(i);
    const got: boolean[] = [];
    for (let i = 0; i < 5; i++)
      got.push(await f.svc.claim(`t${i}`, { machineId: `m${i}` }));
    expect(got).toEqual([true, true, true, false, false]); // 3 per domain per day
    const g = fixture({ idp: 'github' });
    for (let i = 0; i < 4; i++) g.addTenant(i);
    expect(
      await g.svc.claim('t0', { machineId: 'a', ekFingerprint: 'ek1' }),
    ).toBe(true);
    expect(
      await g.svc.claim('t1', { machineId: 'b', ekFingerprint: 'ek1' }),
    ).toBe(false); // same TPM
    const ip = fixture({ idp: 'github' });
    for (let i = 0; i < 7; i++) ip.addTenant(i);
    const r: boolean[] = [];
    for (let i = 0; i < 7; i++)
      r.push(
        await ip.svc.claim(`t${i}`, { machineId: `m${i}`, ip: '203.0.113.9' }),
      );
    expect(r.filter(Boolean)).toHaveLength(5); // 5 per address per day
  });

  it('derives trial_end from the claim time so a retry sends the same parameters', async () => {
    const f = fixture();
    f.addTenant(1);
    await f.svc.claim('t1', { machineId: 'm' });
    const params = f.create.mock.calls[0]![0] as unknown as {
      trial_end: number;
    };
    const claimed = f.claims[0]!.claimedAt!;
    const want = new Date(claimed);
    want.setUTCMonth(want.getUTCMonth() + 3);
    expect(params.trial_end).toBe(Math.floor(want.getTime() / 1000));
  });
});
