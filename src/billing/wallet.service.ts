import { Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { BillingTickService } from './billing-tick.service';
import { EntitlementsService } from './entitlements.service';
import {
  CREDITS_PER_PACK,
  CREDIT_VALID_MONTHS,
  PACK_CENTS,
  PRO_INCLUDED_DEVICES,
  SEAT_PLANS,
  TOP_UP_BELOW_CREDITS,
  TOP_UP_MAX_PER_MONTH,
  TOP_UP_PACKS,
  monthOf,
} from './plans';
import { PRICE, StripeGateway } from './stripe.gateway';
import {
  UsageMeterService,
  allowanceFor,
  balanceOf,
  defaultCap,
} from './usage-meter.service';

const DAY_MS = 86_400_000;
/** A top-up claim older than this is stale (the process died mid-charge). */
const TOP_UP_CLAIM_MS = 15 * 60_000;
/** Cents per credit: $5 / 1,000. */
const CENTS_PER_CREDIT = PACK_CENTS / CREDITS_PER_PACK;
/** Monthly fees in cents, for the bill so far and the forecast (yearly fees are paid up front). */
const PRO_CENTS = 500;
const EXTRA_DEVICE_CENTS = 200;
const SEAT_CENTS = 1500;

function addMonths(at: Date, months: number): Date {
  const d = new Date(at);
  d.setUTCMonth(d.getUTCMonth() + months);
  return d;
}

/**
 * The credit wallet (workspace spec 2026-11-04-payg, 4.3 and 6): the usage page, cap and auto
 * top-up settings, adding paid lots from Stripe, and the auto top-up charge itself.
 */
@Injectable()
export class WalletService implements OnModuleInit {
  private readonly logger = new Logger(WalletService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
    private readonly stripe: StripeGateway,
    private readonly tick: BillingTickService,
    private readonly meter: UsageMeterService,
  ) {}

  /** A spend that leaves the balance low starts an auto top-up in the background (HTTP app). */
  onModuleInit(): void {
    if (this.stripe.configured)
      this.meter.onLowBalance = (tenantId) => void this.maybeTopUp(tenantId);
  }

  /** `GET /billing/usage`: this month's use, the wallet, the bill so far and a forecast. */
  async usage(tenantId: string, now = new Date()) {
    const e = await this.entitlements.get(tenantId);
    const month = monthOf(now);
    const [m, wallet, balance, expiring, row] = await Promise.all([
      this.control.usageMonth.findUnique({
        where: { tenantId_month: { tenantId, month } },
      }),
      this.control.creditWallet.findUnique({ where: { tenantId } }),
      balanceOf(this.control, tenantId, now),
      this.control.creditLot.findMany({
        where: {
          tenantId,
          remaining: { gt: 0 },
          expiresAt: { gt: now, lte: new Date(now.getTime() + 30 * DAY_MS) },
        },
        orderBy: { expiresAt: 'asc' },
        select: { remaining: true, expiresAt: true },
      }),
      this.control.tenantEntitlement.findUnique({ where: { tenantId } }),
    ]);
    const seatPlan = SEAT_PLANS.has(e.plan);
    const kind = seatPlan ? 'seat' : 'device';
    const active = await this.tick.activeCount(tenantId, kind, month);
    const onTheirWay = await this.onTheirWay(tenantId, kind, month);
    const cap = wallet ? wallet.capCredits : defaultCap(e.plan);
    const spent = m?.creditsSpent ?? 0;

    const daysInMonth = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 0),
    ).getUTCDate();
    const elapsed = Math.max(1, now.getUTCDate());
    const creditsForecast = Math.min(
      cap ?? Number.MAX_SAFE_INTEGER,
      Math.round((spent * daysInMonth) / elapsed),
    );
    const extras = (n: number) => {
      if (e.plan === 'pro') return Math.max(0, n - PRO_INCLUDED_DEVICES);
      if (e.plan !== 'company') return 0;
      return Math.max(3, e.committedSeats ?? 0, n) - (e.committedSeats ?? 0);
    };
    const yearly = row?.billingInterval === 'year';
    const baseCents =
      e.plan === 'pro' && row?.stripeSubscriptionId && !yearly ? PRO_CENTS : 0;
    const unitCents = e.plan === 'pro' ? EXTRA_DEVICE_CENTS : SEAT_CENTS;
    const billed = !!row?.stripeSubscriptionId;
    const extrasNow = billed ? extras(active) : 0;
    const extrasForecast = billed ? extras(active + onTheirWay) : 0;
    return {
      month,
      plan: e.plan,
      updatedHourly: true,
      allowance: {
        ai: { used: m?.aiUsed ?? 0, included: allowanceFor(e, 'ai', active) },
        cloudMinutes: {
          used: m?.minutesUsed ?? 0,
          included: allowanceFor(e, 'cloud_minute', active),
        },
      },
      wallet: {
        // Every plan may buy credits, Free included (founder, 4 Nov).
        available: true,
        balance,
        expiringSoon: expiring.map((l) => ({
          credits: l.remaining,
          expiresAt: l.expiresAt.toISOString(),
        })),
        capCredits: cap,
        creditsSpent: spent,
        autoTopUp: wallet?.autoTopUp ?? false,
        topUpsThisMonth: m?.topUps ?? 0,
      },
      active: { kind, count: active, onTheirWay },
      bill: {
        currency: 'usd',
        soFarCents: baseCents + extrasNow * unitCents,
        forecastCents:
          baseCents +
          extrasForecast * unitCents +
          Math.round(Math.max(0, creditsForecast - spent) * CENTS_PER_CREDIT),
        extraUnitsSoFar: extrasNow,
        extraUnitsForecast: extrasForecast,
        creditsForecast,
      },
      alerts: this.banner(e.plan, m, cap, balance, wallet?.autoTopUp ?? false, {
        ai: allowanceFor(e, 'ai', active),
        minutes: allowanceFor(e, 'cloud_minute', active),
      }),
    };
  }

  /** Devices or seats seen on 1 or 2 days this month: likely to become active. */
  private async onTheirWay(
    tenantId: string,
    kind: 'device' | 'seat',
    month: string,
  ): Promise<number> {
    const rows = await this.control.$queryRaw<{ n: bigint }[]>`
      SELECT COUNT(*)::bigint AS n FROM (
        SELECT "subjectId" FROM "active_days"
        WHERE "tenantId" = ${tenantId} AND "kind" = ${kind}
          AND to_char("day", 'YYYY-MM') = ${month}
        GROUP BY "subjectId" HAVING COUNT(*) < 3
      ) s`;
    return Number(rows[0]?.n ?? 0);
  }

  /** The console banner, computed on every load from the same numbers as the email alerts. */
  private banner(
    plan: string,
    m: { aiUsed: number; minutesUsed: number; creditsSpent: number } | null,
    cap: number | null,
    balance: number,
    autoTopUp: boolean,
    included: { ai: number; minutes: number },
  ): string[] {
    return thresholdKeys({
      aiUsed: m?.aiUsed ?? 0,
      minutesUsed: m?.minutesUsed ?? 0,
      creditsSpent: m?.creditsSpent ?? 0,
      aiIncluded: included.ai,
      minutesIncluded: included.minutes,
      cap,
      balance,
      autoTopUp,
    });
  }

  /** Owner settings: the monthly cap (USD, null = no cap) and auto top-up. */
  async updateSettings(
    tenantId: string,
    input: { capUsd?: number | null; autoTopUp?: boolean },
  ) {
    const e = await this.entitlements.get(tenantId);
    const capCredits =
      input.capUsd === undefined
        ? undefined
        : input.capUsd === null
          ? null
          : Math.round((input.capUsd * 100) / CENTS_PER_CREDIT);
    await this.control.creditWallet.upsert({
      where: { tenantId },
      create: {
        tenantId,
        capCredits: capCredits === undefined ? defaultCap(e.plan) : capCredits,
        autoTopUp: input.autoTopUp ?? false,
      },
      update: {
        ...(capCredits !== undefined ? { capCredits } : {}),
        ...(input.autoTopUp !== undefined
          ? { autoTopUp: input.autoTopUp }
          : {}),
      },
    });
    return this.usage(tenantId);
  }

  /**
   * Adds the credits a paid Checkout session or invoice bought. The number comes from the paid
   * line items (credit-pack price x quantity), never from metadata. Keyed by the Stripe id, so a
   * replayed webhook adds nothing. Returns the credits added (0 when nothing to add).
   */
  async addPaidLot(
    tenantId: string,
    stripeRef: string,
    source: 'purchase' | 'top_up',
    lines: { lookupKey: string | null; quantity: number | null }[],
    paidAt = new Date(),
    paymentRefs: string[] = [],
  ): Promise<number> {
    const packs = lines
      .filter((l) => l.lookupKey === PRICE.CREDITS_1000)
      .reduce((n, l) => n + (l.quantity ?? 0), 0);
    if (packs <= 0) return 0;
    const credits = packs * CREDITS_PER_PACK;
    const r = await this.control.creditLot.createMany({
      data: [
        {
          tenantId,
          source,
          credits,
          remaining: credits,
          expiresAt: addMonths(paidAt, CREDIT_VALID_MONTHS),
          stripeRef,
          paymentRefs,
        },
      ],
      skipDuplicates: true,
    });
    if (source === 'top_up')
      await this.control.creditWallet.updateMany({
        where: { tenantId },
        data: { topUpPendingAt: null },
      });
    return r.count ? credits : 0;
  }

  /**
   * A refund (or a lost dispute, `fraction` 1) takes back that share of the credits the payment
   * bought, from what is left: credits already spent are not clawed back, and a lot never goes
   * below zero. `revoked` is cumulative, so a replayed event takes nothing more. Credits only
   * gate paid extras; nothing here can reach protection.
   */
  async revokeForPayment(
    tenantId: string,
    refs: string[],
    fraction: number,
  ): Promise<number> {
    const share = Math.min(1, Math.max(0, fraction));
    const keys = refs.filter(Boolean);
    if (!keys.length) return 0;
    return this.control.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`wallet:${tenantId}`}))`;
      // Found by any payment intent, charge or invoice/session id that paid for the lot; rows
      // locked so a spend or a release on them waits.
      const lots = await tx.$queryRaw<
        { id: string; credits: number; revoked: number; spent: number }[]
      >`
        SELECT "id", "credits", "revoked", "spent" FROM "credit_lots"
        WHERE "tenantId" = ${tenantId}
          AND ("paymentRefs" && ${keys}::text[] OR "stripeRef" = ANY(${keys}::text[]))
        FOR UPDATE`;
      for (const lot of lots) {
        const target = Math.ceil(lot.credits * share);
        if (target <= lot.revoked) continue;
        await tx.creditLot.update({
          where: { id: lot.id },
          data: {
            revoked: target,
            remaining: Math.max(0, lot.credits - target - lot.spent),
          },
        });
      }
      return lots.length;
    });
  }

  /**
   * Auto top-up: 2 packs on an invoice charged to the saved card, at most 3 a month, one at a
   * time. The lot is added by the `invoice.paid` webhook, not here. Never throws.
   */
  async maybeTopUp(tenantId: string, now = new Date()): Promise<boolean> {
    try {
      const month = monthOf(now);
      const claimed = await this.control.$transaction(async (tx) => {
        const w = await tx.creditWallet.updateMany({
          where: {
            tenantId,
            autoTopUp: true,
            OR: [
              { topUpPendingAt: null },
              {
                topUpPendingAt: {
                  lt: new Date(now.getTime() - TOP_UP_CLAIM_MS),
                },
              },
            ],
          },
          data: { topUpPendingAt: now },
        });
        if (w.count !== 1) return false;
        const m = await tx.usageMonth.upsert({
          where: { tenantId_month: { tenantId, month } },
          create: { tenantId, month },
          update: {},
        });
        if (
          m.topUps >= TOP_UP_MAX_PER_MONTH ||
          (await balanceOf(tx, tenantId, now)) >= TOP_UP_BELOW_CREDITS
        ) {
          await tx.creditWallet.update({
            where: { tenantId },
            data: { topUpPendingAt: null },
          });
          return false;
        }
        await tx.usageMonth.update({
          where: { tenantId_month: { tenantId, month } },
          data: { topUps: { increment: 1 } },
        });
        return true;
      });
      if (!claimed) return false;
      await this.chargeTopUp(tenantId, month);
      return true;
    } catch (error) {
      this.logger.error(
        `auto top-up failed for tenant "${tenantId}": ${String(error)}`,
      );
      // A failed charge turns auto top-up off so it does not retry against a declining card.
      await this.control.creditWallet
        .updateMany({
          where: { tenantId },
          data: { topUpPendingAt: null, autoTopUp: false },
        })
        .catch(() => undefined);
      return false;
    }
  }

  private async chargeTopUp(tenantId: string, month: string) {
    const row = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (!row?.stripeCustomerId) throw new Error('no Stripe customer');
    const stripe = this.stripe.client();
    const price = await this.stripe.price(PRICE.CREDITS_1000);
    const m = await this.control.usageMonth.findUniqueOrThrow({
      where: { tenantId_month: { tenantId, month } },
    });
    // The n-th top-up of the month has one idempotency key: a retry never charges twice.
    const key = `manar-topup-${tenantId}-${month}-${m.topUps}`;
    const invoice = await stripe.invoices.create(
      {
        customer: row.stripeCustomerId,
        collection_method: 'charge_automatically',
        automatic_tax: { enabled: true },
        auto_advance: false,
        pending_invoice_items_behavior: 'exclude',
        metadata: { tenantId, purpose: 'credit_top_up' },
      },
      { idempotencyKey: `${key}-invoice` },
    );
    await stripe.invoiceItems.create(
      {
        customer: row.stripeCustomerId,
        invoice: invoice.id,
        pricing: { price },
        quantity: TOP_UP_PACKS,
      },
      { idempotencyKey: `${key}-item` },
    );
    await stripe.invoices.finalizeInvoice(
      invoice.id,
      {},
      { idempotencyKey: `${key}-final` },
    );
    const paid = await stripe.invoices.pay(
      invoice.id,
      {},
      { idempotencyKey: `${key}-pay` },
    );
    if (paid.status !== 'paid')
      throw new Error(`top-up invoice ${paid.status}`);
  }
}

/** Alert and banner keys crossed by this month's numbers (50/80/100% and low credits). */
export function thresholdKeys(n: {
  aiUsed: number;
  minutesUsed: number;
  creditsSpent: number;
  aiIncluded: number;
  minutesIncluded: number;
  cap: number | null;
  balance: number;
  autoTopUp: boolean;
}): string[] {
  const keys: string[] = [];
  const steps = (name: string, used: number, of: number) => {
    if (of <= 0) return;
    for (const p of [50, 80, 100])
      if (used * 100 >= of * p) keys.push(`${name}:${p}`);
  };
  steps('ai', n.aiUsed, n.aiIncluded);
  steps('minutes', n.minutesUsed, n.minutesIncluded);
  if (n.cap !== null) steps('cap', n.creditsSpent, n.cap);
  // Low credits matter only to someone who has credits (or is spending them) and whose
  // allowance is nearly used; someone with none gets the 100% allowance alert instead.
  const nearlyUsed =
    n.aiUsed * 100 >= n.aiIncluded * 80 ||
    (n.minutesIncluded > 0 && n.minutesUsed * 100 >= n.minutesIncluded * 80);
  if (
    !n.autoTopUp &&
    n.balance < TOP_UP_BELOW_CREDITS &&
    (n.creditsSpent > 0 || (n.balance > 0 && nearlyUsed))
  )
    keys.push('credits:low');
  return keys;
}
