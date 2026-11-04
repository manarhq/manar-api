import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import { EntitlementsService } from './entitlements.service';
import { BillingTickService } from './billing-tick.service';
import { PLAN_TABLE, monthOf } from './plans';
import { UsageMeterService } from './usage-meter.service';
import { WalletService } from './wallet.service';

/** Real Postgres (the unit job's control DB with migrations applied); skipped without it. */
const url = process.env.CONTROL_DATABASE_URL;

const day = (iso: string) => new Date(`${iso}T12:00:00.000Z`);

describe.skipIf(!url)(
  'billing tick, wallet and meter reports (postgres)',
  () => {
    const control = new ControlPrismaService({ get: () => url } as never);
    const ids: string[] = [];
    let hosts: { id: string; ownerSubject: string | null; lastSeenAt: Date }[] =
      [];
    let people: { keycloakSubject: string; lastSeenAt: Date }[] = [];
    const tenants = {
      getClient: () =>
        Promise.resolve({
          host: { findMany: () => Promise.resolve(hosts) },
          userProfile: { findMany: () => Promise.resolve(people) },
        }),
    };
    const meterEvent = vi.fn((a: unknown) => {
      void a;
      return Promise.resolve();
    });
    const stripe = { configured: true, meterEvent };
    const tick = new BillingTickService(
      control,
      tenants as never,
      stripe as never,
    );

    const tenant = async (
      plan: 'pro' | 'company',
      extra: Record<string, unknown> = {},
    ) => {
      const t = await control.tenant.create({
        data: {
          slug: `tick-${randomUUID().slice(0, 8)}`,
          name: 'tick',
          kind: plan === 'pro' ? 'PERSONAL' : 'COMPANY',
          status: 'ACTIVE',
        },
      });
      ids.push(t.id);
      await control.tenantEntitlement.create({
        data: {
          tenantId: t.id,
          plan,
          stripeCustomerId: `cus_${t.id}`,
          stripeSubscriptionId: `sub_${t.id}`,
          ...extra,
        },
      });
      return t.id;
    };
    const seeDevices = async (tenantId: string, n: number, days: string[]) => {
      for (const d of days) {
        hosts = Array.from({ length: n }, (_, i) => ({
          id: `h${i}`,
          ownerSubject: `u${i % 2}`,
          lastSeenAt: day(d),
        }));
        people = [];
        await tick.markActiveDays(tenantId, day(d));
      }
    };

    beforeAll(() => control.$connect());
    afterAll(async () => {
      const where = { tenantId: { in: ids } };
      await control.activeDay.deleteMany({ where });
      await control.meterReport.deleteMany({ where });
      await control.creditLot.deleteMany({ where });
      await control.creditWallet.deleteMany({ where });
      await control.usageMonth.deleteMany({ where });
      await control.tenantEntitlement.deleteMany({ where });
      await control.tenant.deleteMany({ where: { id: { in: ids } } });
      await control.$disconnect();
    });

    it('a device is active after 3 different days; repeated ticks add nothing', async () => {
      const t = await tenant('pro');
      await seeDevices(t, 5, ['2026-11-01', '2026-11-02']);
      expect(await tick.activeCount(t, 'device', '2026-11')).toBe(0);
      await seeDevices(t, 5, ['2026-11-02', '2026-11-03', '2026-11-03']);
      expect(await tick.activeCount(t, 'device', '2026-11')).toBe(5);
      // Seats come from device owners too (u0, u1).
      expect(await tick.activeCount(t, 'seat', '2026-11')).toBe(2);
    });

    it('Pro: reports only the devices beyond 2, once, and only the increase', async () => {
      const t = await tenant('pro');
      await seeDevices(t, 4, ['2026-11-01', '2026-11-02', '2026-11-03']);
      const now = day('2026-11-03');
      expect(await tick.queueReports(t, 'pro', null, now)).toBe(1);
      expect(await tick.queueReports(t, 'pro', null, now)).toBe(0);
      await seeDevices(t, 6, ['2026-11-01', '2026-11-02', '2026-11-03']);
      expect(await tick.queueReports(t, 'pro', null, now)).toBe(1);
      const rows = await control.meterReport.findMany({
        where: { tenantId: t },
        orderBy: { createdAt: 'asc' },
      });
      expect(rows.map((r) => r.value)).toEqual([2, 2]);
      expect(rows.reduce((n, r) => n + r.value, 0)).toBe(4); // 6 active - 2 included
    });

    it('Company monthly: 3 seats minimum as soon as the month starts, then each active seat', async () => {
      const t = await tenant('company');
      expect(
        await tick.queueReports(t, 'company', null, day('2026-11-01')),
      ).toBe(1);
      const first = await control.meterReport.findFirstOrThrow({
        where: { tenantId: t },
      });
      expect(first).toMatchObject({
        meter: 'manar_company_seats',
        value: 3,
        month: '2026-11',
      });
    });

    it('last month is topped up only if it was already being billed', async () => {
      const t = await tenant('pro');
      await seeDevices(t, 3, ['2026-10-29', '2026-10-30', '2026-10-31']);
      // A new subscriber on 1 Nov is not billed for October.
      expect(await tick.queueReports(t, 'pro', null, day('2026-11-01'))).toBe(
        0,
      );
    });

    it('sends the queue with its identifiers; Stripe down leaves it queued for the next tick', async () => {
      const t = await tenant('pro');
      await seeDevices(t, 3, ['2026-11-01', '2026-11-02', '2026-11-03']);
      await tick.queueReports(t, 'pro', null, day('2026-11-03'));
      meterEvent.mockRejectedValueOnce(new Error('stripe down'));
      const down = await tick.flush();
      expect(down.failed).toBe(1);
      const queued = await control.meterReport.findFirstOrThrow({
        where: { tenantId: t },
      });
      expect(queued.reportedAt).toBeNull();
      await tick.flush();
      expect(meterEvent).toHaveBeenLastCalledWith({
        meter: 'manar_pro_extra_devices',
        customer: `cus_${t}`,
        value: 1,
        identifier: `${t}:manar_pro_extra_devices:2026-11:1`,
      });
      expect(
        (await control.meterReport.findFirstOrThrow({ where: { tenantId: t } }))
          .reportedAt,
      ).not.toBeNull();
    });

    it('an identifier Stripe already has counts as sent; a 4xx skips only that report', async () => {
      const t = await tenant('pro');
      await seeDevices(t, 4, ['2026-11-01', '2026-11-02', '2026-11-03']);
      await tick.queueReports(t, 'pro', null, day('2026-11-03'));
      meterEvent.mockRejectedValueOnce(
        Object.assign(new Error('An event already exists with identifier x.'), {
          statusCode: 400,
        }),
      );
      await tick.flush();
      const r = await control.meterReport.findFirstOrThrow({
        where: { tenantId: t },
      });
      expect(r.reportedAt).not.toBeNull();

      const t2 = await tenant('pro');
      const t3 = await tenant('pro');
      for (const x of [t2, t3]) {
        await seeDevices(x, 3, ['2026-11-01', '2026-11-02', '2026-11-03']);
        await tick.queueReports(x, 'pro', null, day('2026-11-03'));
      }
      meterEvent.mockRejectedValueOnce(
        Object.assign(new Error('No such customer'), { statusCode: 400 }),
      );
      const out = await tick.flush();
      expect(out.failed).toBe(1);
      const sent = await control.meterReport.findFirstOrThrow({
        where: { tenantId: t3 },
      });
      expect(sent.reportedAt).not.toBeNull();
    });

    describe('wallet', () => {
      const entitlements = new EntitlementsService(
        control,
        { get: () => 'https://c.example' } as never,
        { recordSafely: () => Promise.resolve() } as never,
        tenants as never,
        { get: vi.fn() } as never,
      );
      const invoices = {
        create: vi.fn(() => Promise.resolve({ id: 'in_1' })),
        finalizeInvoice: vi.fn(() => Promise.resolve({})),
        pay: vi.fn(() => Promise.resolve({ status: 'paid' })),
      };
      const items = { create: vi.fn(() => Promise.resolve({})) };
      const gateway = {
        configured: true,
        price: () => Promise.resolve('price_credits'),
        client: () => ({ invoices, invoiceItems: items }),
      };
      const wallet = new WalletService(
        control,
        entitlements,
        gateway as never,
        tick,
        { onLowBalance: undefined } as never,
      );

      it('adds a paid lot once, valid 12 months, from the pack lines only', async () => {
        const t = await tenant('pro');
        const lines = [
          { lookupKey: 'manar_credits_1000_v2', quantity: 2 },
          { lookupKey: 'manar_pro_monthly_v2', quantity: 1 },
        ];
        const paidAt = new Date('2026-11-04T00:00:00Z');
        expect(
          await wallet.addPaidLot(t, `cs_${t}`, 'purchase', lines, paidAt),
        ).toBe(2000);
        expect(
          await wallet.addPaidLot(t, `cs_${t}`, 'purchase', lines, paidAt),
        ).toBe(0);
        const lot = await control.creditLot.findFirstOrThrow({
          where: { tenantId: t },
        });
        expect(lot).toMatchObject({ credits: 2000, remaining: 2000 });
        expect(lot.expiresAt.toISOString()).toBe('2027-11-04T00:00:00.000Z');
        expect(
          await wallet.addPaidLot(t, `cs2_${t}`, 'purchase', [lines[1]!]),
        ).toBe(0);
      });

      it('auto top-up: only when on, under $2, at most 3 a month, one at a time', async () => {
        const t = await tenant('pro');
        expect(await wallet.maybeTopUp(t)).toBe(false); // off by default
        await wallet.updateSettings(t, { autoTopUp: true });
        expect(await wallet.maybeTopUp(t)).toBe(true);
        expect(items.create).toHaveBeenLastCalledWith(
          expect.objectContaining({
            quantity: 2,
            pricing: { price: 'price_credits' },
          }),
          expect.anything(),
        );
        // The claim is held until the webhook adds the lot: a second call does nothing.
        expect(await wallet.maybeTopUp(t)).toBe(false);
        await wallet.addPaidLot(t, `in_a_${t}`, 'top_up', [
          { lookupKey: 'manar_credits_1000_v2', quantity: 2 },
        ]);
        // Balance is 2,000 now: no top-up.
        expect(await wallet.maybeTopUp(t)).toBe(false);
        await control.creditLot.updateMany({
          where: { tenantId: t },
          data: { remaining: 0 },
        });
        expect(await wallet.maybeTopUp(t)).toBe(true);
        await wallet.addPaidLot(t, `in_b_${t}`, 'top_up', []);
        await control.creditWallet.update({
          where: { tenantId: t },
          data: { topUpPendingAt: null },
        });
        expect(await wallet.maybeTopUp(t)).toBe(true);
        await control.creditWallet.update({
          where: { tenantId: t },
          data: { topUpPendingAt: null },
        });
        expect(await wallet.maybeTopUp(t)).toBe(false); // 3 this month already
        const m = await control.usageMonth.findUniqueOrThrow({
          where: { tenantId_month: { tenantId: t, month: monthOf() } },
        });
        expect(m.topUps).toBe(3);
      });

      it('a declined top-up turns auto top-up off', async () => {
        const t = await tenant('pro');
        await wallet.updateSettings(t, { autoTopUp: true });
        invoices.pay.mockResolvedValueOnce({ status: 'open' });
        expect(await wallet.maybeTopUp(t)).toBe(false);
        const w = await control.creditWallet.findUniqueOrThrow({
          where: { tenantId: t },
        });
        expect(w).toMatchObject({ autoTopUp: false, topUpPendingAt: null });
      });

      it('usage page: allowance, balance, active devices, bill so far and forecast', async () => {
        const t = await tenant('pro');
        const now = day('2026-11-03');
        await seeDevices(t, 4, ['2026-11-01', '2026-11-02', '2026-11-03']);
        await control.usageMonth.create({
          data: {
            tenantId: t,
            month: '2026-11',
            aiUsed: 300,
            creditsSpent: 30,
          },
        });
        await wallet.addPaidLot(
          t,
          `cs_u_${t}`,
          'purchase',
          [{ lookupKey: 'manar_credits_1000_v2', quantity: 1 }],
          now,
        );
        const u = await wallet.usage(t, now);
        expect(u.allowance.ai).toEqual({ used: 300, included: 300 });
        expect(u.wallet).toMatchObject({
          available: true,
          balance: 1000,
          capCredits: 4000,
        });
        expect(u.active).toEqual({ kind: 'device', count: 4, onTheirWay: 0 });
        // $5 base + 2 extra devices x $2.
        expect(u.bill.soFarCents).toBe(900);
        // 30 credits in 3 days -> 300 in a 30-day month: 270 more credits = $1.35.
        expect(u.bill.creditsForecast).toBe(300);
        expect(u.bill.forecastCents).toBe(900 + 135);
        expect(u.alerts).toContain('ai:100');
        expect(PLAN_TABLE.pro.allowance.ai).toBe(300);
      });

      it('a refund takes back unspent credits in proportion, never below zero, and only once', async () => {
        const t = await tenant('pro');
        await wallet.addPaidLot(
          t,
          `cs_rf_${t}`,
          'purchase',
          [{ lookupKey: 'manar_credits_1000_v2', quantity: 2 }],
          new Date(),
          [`pi_rf_${t}`, `ch_rf_${t}`],
        );
        // 2,000 bought, 1,700 already spent.
        await control.creditLot.updateMany({
          where: { tenantId: t },
          data: { remaining: 300, spent: 1700 },
        });
        await wallet.revokeForPayment(t, [`pi_rf_${t}`], 0.1); // 200 credits taken back
        let lot = await control.creditLot.findFirstOrThrow({
          where: { tenantId: t },
        });
        expect(lot).toMatchObject({ remaining: 100, revoked: 200 });
        // The same refund event again changes nothing.
        await wallet.revokeForPayment(t, [`pi_rf_${t}`], 0.1);
        lot = await control.creditLot.findFirstOrThrow({
          where: { tenantId: t },
        });
        expect(lot.remaining).toBe(100);
        // A full refund (or a lost dispute) leaves 0, not a negative balance.
        await wallet.revokeForPayment(t, [`pi_rf_${t}`], 1);
        lot = await control.creditLot.findFirstOrThrow({
          where: { tenantId: t },
        });
        expect(lot).toMatchObject({ remaining: 0, revoked: 2000 });
        // Found by the charge as well, and by the session/invoice id the lot is keyed by.
        expect(await wallet.revokeForPayment(t, [`ch_rf_${t}`], 1)).toBe(1);
        expect(await wallet.revokeForPayment(t, [`cs_rf_${t}`], 1)).toBe(1);
        // Another tenant's payment id never touches this wallet.
        await wallet.revokeForPayment('someone-else', [`pi_rf_${t}`], 1);
      });

      describe('refunds against spends and releases (real meter)', () => {
        const meter = new UsageMeterService(control, entitlements);
        const paid = async (t: string, ref: string, packs = 1) => {
          await control.usageMonth.upsert({
            where: { tenantId_month: { tenantId: t, month: monthOf() } },
            create: { tenantId: t, month: monthOf(), aiUsed: 300 },
            update: { aiUsed: 300 },
          });
          await wallet.addPaidLot(
            t,
            `cs_${ref}`,
            'purchase',
            [{ lookupKey: 'manar_credits_1000_v2', quantity: packs }],
            new Date(),
            [ref],
          );
        };
        const lotOf = (t: string) =>
          control.creditLot.findFirstOrThrow({ where: { tenantId: t } });

        it('a partial refund after a partial spend leaves exactly what is still owed', async () => {
          const t = await tenant('pro');
          await paid(t, `pi_ps_${t}`);
          for (let i = 0; i < 30; i++) await meter.consume(t, 'ai', `s${i}`);
          await wallet.revokeForPayment(t, [`pi_ps_${t}`], 0.5); // 500 back, 500 owed
          expect(await lotOf(t)).toMatchObject({
            remaining: 470,
            spent: 30,
            revoked: 500,
          });
          await wallet.revokeForPayment(t, [`pi_ps_${t}`], 0.98); // 980 back, 20 owed
          // Entitled 20, spent 30: nothing left, and no further spend is possible.
          expect(await lotOf(t)).toMatchObject({
            remaining: 0,
            spent: 30,
            revoked: 980,
          });
          await expect(meter.consume(t, 'ai', 'more')).rejects.toMatchObject({
            reason: 'credits_exhausted',
          });
        });

        it('a release after a refund cannot bring back refunded value', async () => {
          const t = await tenant('pro');
          await paid(t, `pi_rr_${t}`);
          for (let i = 0; i < 10; i++) await meter.consume(t, 'ai', `r${i}`);
          await wallet.revokeForPayment(t, [`pi_rr_${t}`], 1); // fully refunded
          await meter.release(t, 'r0');
          await meter.release(t, 'r1');
          expect(await lotOf(t)).toMatchObject({
            remaining: 0,
            revoked: 1000,
            spent: 8,
          });
          // 95% refunded (entitled 50) with 60 spent: the 10 over are a debt that releases pay first.
          const t2 = await tenant('pro');
          await paid(t2, `pi_rr2_${t2}`);
          for (let i = 0; i < 60; i++) await meter.consume(t2, 'ai', `q${i}`);
          await wallet.revokeForPayment(t2, [`pi_rr2_${t2}`], 0.95);
          expect((await lotOf(t2)).remaining).toBe(0);
          for (let i = 0; i < 10; i++) await meter.release(t2, `q${i}`);
          expect((await lotOf(t2)).remaining).toBe(0); // 50 spent, 50 owed
          await meter.release(t2, 'q10');
          expect((await lotOf(t2)).remaining).toBe(1);
        });

        it('concurrent refund and releases end in the same place as any order', async () => {
          const t = await tenant('pro');
          await paid(t, `pi_cc_${t}`);
          for (let i = 0; i < 100; i++) await meter.consume(t, 'ai', `c${i}`);
          await Promise.all([
            wallet.revokeForPayment(t, [`pi_cc_${t}`], 0.5),
            ...Array.from({ length: 20 }, (_, i) => meter.release(t, `c${i}`)),
          ]);
          // 1000 bought, 500 refunded, 80 spent after releases: 420 left.
          expect(await lotOf(t)).toMatchObject({
            spent: 80,
            revoked: 500,
            remaining: 420,
          });
        });
      });

      it('cap settings: USD to credits, null for no cap', async () => {
        const t = await tenant('pro');
        await wallet.updateSettings(t, { capUsd: 50 });
        expect(
          (
            await control.creditWallet.findUniqueOrThrow({
              where: { tenantId: t },
            })
          ).capCredits,
        ).toBe(10000);
        await wallet.updateSettings(t, { capUsd: null });
        expect(
          (
            await control.creditWallet.findUniqueOrThrow({
              where: { tenantId: t },
            })
          ).capCredits,
        ).toBeNull();
      });
    });
  },
);
