import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import type { Entitlement } from './entitlements.service';
import { PLAN_TABLE, monthOf } from './plans';
import { UsageMeterService, UsagePausedError } from './usage-meter.service';

/** Real Postgres (the unit job's control DB with migrations applied); skipped without it. */
const url = process.env.CONTROL_DATABASE_URL;

const ent = (plan: Entitlement['plan'], extra: Partial<Entitlement> = {}) => ({
  plan,
  status: 'active' as Entitlement['status'],
  ...PLAN_TABLE[plan === 'enterprise' ? 'company' : plan],
  ...extra,
});

describe.skipIf(!url)('UsageMeterService (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const tenants: string[] = [];
  let current: Entitlement = ent('free');
  const entitlements = {
    get: vi.fn(() => Promise.resolve(current)),
    upgradeUrl: () => 'https://c.example/settings/billing',
  };
  const meter = new UsageMeterService(control, entitlements as never);
  const tenant = () => {
    const t = `meter-${randomUUID()}`;
    tenants.push(t);
    return t;
  };
  const lot = (tenantId: string, credits: number, expiresInDays: number) =>
    control.creditLot.create({
      data: {
        tenantId,
        source: 'purchase',
        credits,
        remaining: credits,
        expiresAt: new Date(Date.now() + expiresInDays * 86_400_000),
      },
    });
  const setMonth = (tenantId: string, aiUsed: number, creditsSpent = 0) =>
    control.usageMonth.create({
      data: { tenantId, month: monthOf(), aiUsed, creditsSpent },
    });
  const reason = (p: Promise<unknown>) =>
    p.then(
      () => 'allowed',
      (e: unknown) =>
        e instanceof UsagePausedError
          ? e.reason
          : `error:${(e as { getStatus?: () => number }).getStatus?.()}`,
    );

  beforeAll(() => control.$connect());
  afterAll(async () => {
    const where = { tenantId: { in: tenants } };
    await control.usageEvent.deleteMany({ where });
    await control.usageMonth.deleteMany({ where });
    await control.creditLot.deleteMany({ where });
    await control.creditWallet.deleteMany({ where });
    await control.$disconnect();
  });

  it('Free: 20 AI actions a month, then credits (Free may buy packs), then paused', async () => {
    current = ent('free');
    const t = tenant();
    await setMonth(t, 19);
    expect(await meter.consume(t, 'ai', 'k1')).toEqual({ source: 'allowance' });
    expect(await reason(meter.consume(t, 'ai', 'k2'))).toBe(
      'credits_exhausted',
    );
    // A refusal leaves no trace.
    expect(await control.usageEvent.count({ where: { tenantId: t } })).toBe(1);
    // Free has no cap (credits are prepaid): a $5 pack is spent.
    await lot(t, 1, 30);
    expect((await meter.consume(t, 'ai', 'k3')).source).toBe('credits');
    expect(await reason(meter.consume(t, 'ai', 'k4'))).toBe(
      'credits_exhausted',
    );
  });

  it('the same key is counted once (a retry or the same cloud minute)', async () => {
    current = ent('pro');
    const t = tenant();
    await meter.consume(t, 'cloud_minute', 'cm:a:2026-11-04T10:00');
    expect(
      await meter.consume(t, 'cloud_minute', 'cm:a:2026-11-04T10:00'),
    ).toEqual({ source: 'duplicate' });
    const m = await control.usageMonth.findUniqueOrThrow({
      where: { tenantId_month: { tenantId: t, month: monthOf() } },
    });
    expect(m.minutesUsed).toBe(1);
  });

  it('Pro above 300: spends credits from the lot that expires first, skipping expired ones', async () => {
    current = ent('pro');
    const t = tenant();
    await setMonth(t, 300);
    const late = await lot(t, 5, 300);
    const soon = await lot(t, 5, 10);
    await control.creditLot.create({
      data: {
        tenantId: t,
        source: 'purchase',
        credits: 50,
        remaining: 50,
        expiresAt: new Date(Date.now() - 1000),
      },
    });
    const r = await meter.consume(t, 'ai', 'p1');
    expect(r).toEqual({ source: 'credits', balance: 9 });
    expect(
      (await control.creditLot.findUniqueOrThrow({ where: { id: soon.id } }))
        .remaining,
    ).toBe(4);
    expect(
      (await control.creditLot.findUniqueOrThrow({ where: { id: late.id } }))
        .remaining,
    ).toBe(5);
  });

  it('no credits left: paused with "credits_exhausted"', async () => {
    current = ent('pro');
    const t = tenant();
    await setMonth(t, 300);
    expect(await reason(meter.consume(t, 'ai', 'x'))).toBe('credits_exhausted');
  });

  it('the monthly cap pauses paid extras ($20 default on Pro = 4,000 credits)', async () => {
    current = ent('pro');
    const t = tenant();
    await setMonth(t, 300, 4000);
    await lot(t, 1000, 30);
    expect(await reason(meter.consume(t, 'ai', 'c1'))).toBe(
      'spend_cap_reached',
    );
    // The owner raises the cap: it works again.
    await control.creditWallet.create({
      data: { tenantId: t, capCredits: 5000 },
    });
    expect((await meter.consume(t, 'ai', 'c2')).source).toBe('credits');
    // No cap at all.
    await control.creditWallet.update({
      where: { tenantId: t },
      data: { capCredits: null },
    });
    expect((await meter.consume(t, 'ai', 'c3')).source).toBe('credits');
  });

  it('a frozen (disputed) or read-only workspace gets no paid extras', async () => {
    const t = tenant();
    current = ent('pro', { status: 'frozen' });
    expect(await reason(meter.consume(t, 'ai', 'f'))).toBe(
      'paid_features_paused',
    );
    current = ent('company_trial', { status: 'read_only' });
    expect(await reason(meter.consume(t, 'ai', 'r'))).toBe(
      'paid_features_paused',
    );
  });

  it('Company pools 300 per seat over at least 3 seats (and the committed number)', async () => {
    const t = tenant();
    current = ent('company');
    await setMonth(t, 899);
    expect((await meter.consume(t, 'ai', 's1')).source).toBe('allowance');
    expect(await reason(meter.consume(t, 'ai', 's2'))).toBe(
      'credits_exhausted',
    );
    current = ent('company', { committedSeats: 10 });
    expect((await meter.consume(t, 'ai', 's3')).source).toBe('allowance');
  });

  it('a database error refuses the paid extra (503), never allows it', async () => {
    current = ent('pro');
    const broken = new UsageMeterService(
      { $transaction: () => Promise.reject(new Error('db down')) } as never,
      entitlements as never,
    );
    expect(await reason(broken.consume(tenant(), 'ai', 'e'))).toBe('error:503');
  });

  it('concurrent uses never spend more credits than there are', async () => {
    current = ent('pro');
    const t = tenant();
    await setMonth(t, 300);
    await lot(t, 7, 30);
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        reason(meter.consume(t, 'ai', `c${i}`)),
      ),
    );
    expect(results.filter((r) => r === 'allowed')).toHaveLength(7);
    expect(results.filter((r) => r === 'credits_exhausted')).toHaveLength(13);
    const agg = await control.creditLot.aggregate({
      where: { tenantId: t },
      _sum: { remaining: true },
    });
    expect(agg._sum.remaining).toBe(0);
  });

  it('ai(): an answer that never came is given back, credit included', async () => {
    current = ent('pro');
    const t = tenant();
    await setMonth(t, 300);
    const l = await lot(t, 2, 30);
    await meter.ai(t, () => Promise.resolve({ available: false }));
    await expect(
      meter.ai(t, () => Promise.reject(new Error('boom'))),
    ).rejects.toThrow('boom');
    expect(
      (await control.creditLot.findUniqueOrThrow({ where: { id: l.id } }))
        .remaining,
    ).toBe(2);
    await meter.ai(t, () => Promise.resolve({ available: true }));
    const m = await control.usageMonth.findUniqueOrThrow({
      where: { tenantId_month: { tenantId: t, month: monthOf() } },
    });
    expect(m).toMatchObject({ aiUsed: 301, creditsSpent: 1 });
    expect(
      (await control.creditLot.findUniqueOrThrow({ where: { id: l.id } }))
        .remaining,
    ).toBe(1);
  });

  it('a credit spend that leaves less than $2 asks for an auto top-up', async () => {
    current = ent('pro');
    const t = tenant();
    await setMonth(t, 300);
    await lot(t, 401, 30);
    const low = vi.fn();
    meter.onLowBalance = low;
    await meter.consume(t, 'ai', 'l1');
    expect(low).not.toHaveBeenCalled();
    await meter.consume(t, 'ai', 'l2');
    expect(low).toHaveBeenCalledWith(t);
    meter.onLowBalance = undefined;
  });
});
