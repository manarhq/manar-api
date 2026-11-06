import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import type { Entitlement } from './entitlements.service';
import { PLAN_TABLE } from './plans';
import { UsageMeterService } from './usage-meter.service';
import { WalletService } from './wallet.service';

/** Real Postgres (the unit job's control DB with migrations applied); skipped without it. */
const url = process.env.CONTROL_DATABASE_URL;

describe.skipIf(!url)('GET /billing/usage/daily numbers (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const ent: Entitlement = {
    plan: 'free',
    status: 'active',
    ...PLAN_TABLE.free,
  };
  const entitlements = {
    get: vi.fn(() => Promise.resolve(ent)),
    upgradeUrl: () => 'https://c.example/settings/billing',
  };
  const meter = new UsageMeterService(control, entitlements as never);
  const wallet = new WalletService(
    control,
    entitlements as never,
    { configured: false } as never,
    { activeCount: () => Promise.resolve(0) } as never,
    meter,
  );
  const t = `daily-${randomUUID()}`;
  const other = `daily-${randomUUID()}`;

  beforeAll(() => control.$connect());
  afterAll(async () => {
    const where = { tenantId: { in: [t, other] } };
    await control.usageEvent.deleteMany({ where });
    await control.usageMonth.deleteMany({ where });
    await control.creditLot.deleteMany({ where });
    await control.$disconnect();
  });

  it('adds up to the month on the usage page, splits allowance from credits, and ignores other workspaces and given-back actions', async () => {
    const included = PLAN_TABLE.free.allowance.ai;
    await control.creditLot.create({
      data: {
        tenantId: t,
        source: 'purchase',
        credits: 50,
        remaining: 50,
        expiresAt: new Date(Date.now() + 30 * 86_400_000),
      },
    });
    for (let i = 0; i < included + 3; i++)
      await meter.consume(t, 'ai', `k${i}`);
    await meter.consume(t, 'ai', 'given-back');
    await meter.release(t, 'given-back');
    await meter.consume(other, 'ai', 'someone-else');

    const r = await wallet.dailyAiUsage(t, 30);

    expect(r.days).toHaveLength(30);
    expect(r.days.at(-1)!.date).toBe(new Date().toISOString().slice(0, 10));
    expect(r.totals).toEqual({
      actions: included + 3,
      fromAllowance: included,
      fromCredits: 3,
    });
    expect(r.month).toMatchObject({
      used: included + 3,
      included,
      creditsSpent: 3,
    });
    // Agrees with the meter's own month counters.
    expect(r.totals.actions).toBe(r.month.used);
    expect(r.totals.fromCredits).toBe(r.month.creditsSpent);
    const today = r.days.at(-1)!;
    expect(today.actions).toBe(included + 3);
  });

  it('clamps the window to 1 to 90 days', async () => {
    expect((await wallet.dailyAiUsage(t, 0)).days).toHaveLength(1);
    expect((await wallet.dailyAiUsage(t, 5000)).days).toHaveLength(90);
  });
});
