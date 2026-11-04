import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { EntitlementsService } from './entitlements.service';
import { PRICE } from './stripe.gateway';
import { StripeWebhookService } from './stripe-webhook.service';

const PRICE_IDS: Record<string, string> = {
  [PRICE.CREDITS_1000]: 'price_credits',
  [PRICE.PRO_EXTRA_DEVICE]: 'price_extra',
  [PRICE.COMPANY_SEAT_MONTHLY]: 'price_seat_m',
};
const item = (lookup_key: string, quantity = 1) => ({
  quantity,
  price: { id: `price_${lookup_key}`, lookup_key },
});

function make(rows: Record<string, Record<string, unknown>>) {
  const events = new Set<string>();
  const claims: Record<string, unknown>[] = [];
  const find = (where: { tenantId?: string; stripeCustomerId?: string }) =>
    Object.values(rows).find(
      (r) =>
        (where.tenantId && r.tenantId === where.tenantId) ||
        (where.stripeCustomerId &&
          r.stripeCustomerId === where.stripeCustomerId),
    ) ?? null;
  const control = {
    tenantEntitlement: {
      findUnique: vi.fn(
        ({
          where,
        }: {
          where: { tenantId?: string; stripeCustomerId?: string };
        }) => Promise.resolve(find(where)),
      ),
      upsert: vi.fn(
        ({
          where,
          update,
        }: {
          where: { tenantId: string };
          update: object;
        }) => {
          Object.assign(rows[where.tenantId]!, update);
          return Promise.resolve();
        },
      ),
    },
    stripeEvent: {
      findUnique: vi.fn(({ where }: { where: { id: string } }) =>
        Promise.resolve(events.has(where.id) ? { id: where.id } : null),
      ),
      create: vi.fn(({ data }: { data: { id: string } }) => {
        if (events.has(data.id))
          return Promise.reject(
            Object.assign(new Error('dup'), { code: 'P2002' }),
          );
        events.add(data.id);
        return Promise.resolve();
      }),
    },
    trialClaim: {
      findFirst: vi.fn(({ where }: { where: { tenantId: string } }) =>
        Promise.resolve(
          claims.find((c) => c.tenantId === where.tenantId) ?? null,
        ),
      ),
      create: vi.fn(({ data }: { data: Record<string, unknown> }) => {
        if (
          data.cardFingerprint &&
          claims.some((c) => c.cardFingerprint === data.cardFingerprint)
        )
          return Promise.reject(
            Object.assign(new Error('dup'), { code: 'P2002' }),
          );
        claims.push(data);
        return Promise.resolve(data);
      }),
    },
    tenant: {
      findUnique: vi.fn(() =>
        Promise.resolve({ ownerIssuer: 'iss', ownerSubject: 'owner' }),
      ),
    },
  };
  const audit = { recordSafely: vi.fn(() => Promise.resolve()) };
  const entitlements = new EntitlementsService(
    control as never,
    { get: () => 'https://c.example' } as never,
    audit as never,
    { getClient: () => Promise.resolve({}) } as never,
    { get: vi.fn() } as never,
  );
  let next: unknown = null;
  let live: unknown = null;
  const sub = vi.fn(() => Promise.resolve(live));
  /** What Stripe holds now: every dispute of every charge, whatever event arrives. */
  const disputes: { id: string; charge: string; status: string }[] = [];
  const pms: Record<string, Record<string, unknown>> = {};
  const customerDefaultPm: { id: string | null } = { id: null };
  const stripe = {
    subscriptions: { retrieve: sub, cancel: vi.fn(() => Promise.resolve()) },
    subscriptionItems: { create: vi.fn(() => Promise.resolve()) },
    charges: {
      retrieve: vi.fn((id: string) =>
        Promise.resolve({
          id,
          customer: 'cus_1',
          payment_intent: `pi_${id}`,
          amount: 1000,
          amount_refunded: 0,
        }),
      ),
      list: vi.fn(() => ({
        // eslint-disable-next-line @typescript-eslint/require-await
        async *[Symbol.asyncIterator]() {
          for (const c of new Set(disputes.map((d) => d.charge)))
            yield {
              id: c,
              customer: 'cus_1',
              disputed: true,
              payment_intent: `pi_${c}`,
            };
        },
      })),
    },
    disputes: {
      list: vi.fn(({ charge }: { charge: string }) =>
        Promise.resolve({ data: disputes.filter((d) => d.charge === charge) }),
      ),
    },
    customers: {
      retrieve: vi.fn(() =>
        Promise.resolve({
          invoice_settings: { default_payment_method: customerDefaultPm.id },
        }),
      ),
    },
    setupIntents: {
      retrieve: vi.fn((id: string) =>
        Promise.resolve({
          payment_method: id === 'seti_ok' ? 'pm_from_seti' : null,
        }),
      ),
    },
    paymentMethods: {
      retrieve: vi.fn((id: string) =>
        Promise.resolve(
          pms[id] ?? { type: 'card', card: { fingerprint: `fp_${id}` } },
        ),
      ),
    },
    checkout: {
      sessions: {
        listLineItems: vi.fn(() =>
          Promise.resolve({
            data: [{ price: { id: 'price_credits' }, quantity: 3 }],
          }),
        ),
      },
    },
    invoicePayments: {
      list: vi.fn(() => Promise.resolve({ data: [{ invoice: 'in_paid' }] })),
    },
    invoices: {
      retrieve: vi.fn(() =>
        Promise.resolve({
          id: 'in_top',
          status: 'paid',
          payments: {
            data: [
              { payment: { payment_intent: 'pi_top', charge: 'ch_top' } },
              { payment: { payment_intent: 'pi_top2' } },
            ],
          },
          lines: {
            data: [
              {
                pricing: { price_details: { price: 'price_credits' } },
                quantity: 2,
              },
            ],
          },
        }),
      ),
    },
  };
  const gateway = {
    constructEvent: vi.fn(() => {
      if (next === 'bad') throw new Error('bad signature');
      return next;
    }),
    price: (k: string) => Promise.resolve(PRICE_IDS[k] ?? `price_${k}`),
    client: () => stripe,
  };
  const wallet = {
    addPaidLot: vi.fn(() => Promise.resolve(1000)),
    revokeForPayment: vi.fn(() => Promise.resolve()),
  };
  const svc = new StripeWebhookService(
    control as never,
    entitlements,
    gateway as never,
    wallet as never,
    audit as never,
    { getClient: () => Promise.resolve({}) } as never,
  );
  const send = (event: unknown) => {
    next = event;
    const e = event as { type: string; data: { object: unknown } };
    // Stripe returns the subscription's current state when asked, whatever event woke us.
    if (e.type.startsWith('customer.subscription.'))
      live = e.type.endsWith('deleted')
        ? { ...(e.data.object as object), status: 'canceled' }
        : e.data.object;
    return svc.handle(Buffer.from('{}'), 'sig');
  };
  return {
    svc,
    send,
    rows,
    control,
    audit,
    gateway,
    stripe,
    wallet,
    sub,
    claims,
    disputes,
    pms,
    customerDefaultPm,
    setLive: (v: unknown) => (live = v),
  };
}

const subEvent = (id: string, o: Record<string, unknown> = {}) => ({
  id,
  type: 'customer.subscription.updated',
  data: {
    object: {
      id: 'sub_1',
      customer: 'cus_1',
      status: 'active',
      metadata: { tenantId: 't1' },
      items: { data: [item(PRICE.PRO_MONTHLY), item(PRICE.PRO_EXTRA_DEVICE)] },
      ...o,
    },
  },
});

const row = () => ({
  t1: {
    tenantId: 't1',
    plan: 'free',
    status: 'active',
    stripeCustomerId: 'cus_1',
  },
  t2: {
    tenantId: 't2',
    plan: 'free',
    status: 'active',
    stripeCustomerId: 'cus_2',
  },
});

describe('StripeWebhookService', () => {
  it('a bad signature is a 400 and changes nothing', async () => {
    const { svc, rows, control, gateway } = make(row());
    gateway.constructEvent.mockImplementation(() => {
      throw new Error('No signatures found matching');
    });
    await expect(svc.handle(Buffer.from('{}'), 'x')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(svc.handle(undefined, undefined)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(rows.t1!.plan).toBe('free');
    expect(control.stripeEvent.create).not.toHaveBeenCalled();
  });

  it('maps Pro by lookup key, once; a duplicate delivery is ignored', async () => {
    const { send, rows, audit } = make(row());
    expect(await send(subEvent('evt_1'))).toEqual({ received: true });
    expect(rows.t1).toMatchObject({
      plan: 'pro',
      billingInterval: 'month',
      stripeSubscriptionId: 'sub_1',
    });
    rows.t1!.plan = 'free'; // would flip back to pro if applied twice
    expect(await send(subEvent('evt_1'))).toEqual({
      received: true,
      duplicate: true,
    });
    expect(rows.t1!.plan).toBe('free');
    expect(audit.recordSafely).toHaveBeenCalledTimes(1);
  });

  it("an event whose apply failed is applied on Stripe's retry", async () => {
    const { send, rows, sub } = make(row());
    sub.mockRejectedValueOnce(new Error('process stopped'));
    await expect(send(subEvent('evt_9'))).rejects.toThrow();
    expect(rows.t1!.plan).toBe('free');
    expect(await send(subEvent('evt_9'))).toEqual({ received: true });
    expect(rows.t1!.plan).toBe('pro');
  });

  it('rejects a cross-tenant spoof: metadata names another tenant than the customer', async () => {
    const { send, rows, control } = make(row());
    await expect(
      send(
        subEvent('evt_2', { customer: 'cus_2', metadata: { tenantId: 't1' } }),
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(rows.t1!.plan).toBe('free');
    expect(rows.t2!.plan).toBe('free');
    expect(control.stripeEvent.create).not.toHaveBeenCalled();
    // A customer we never created is ignored with a 200 (a 4xx would only make Stripe retry).
    expect(
      await send(
        subEvent('evt_3', {
          customer: 'cus_evil',
          metadata: { tenantId: 't1' },
        }),
      ),
    ).toEqual({ received: true });
    expect(rows.t1!.plan).toBe('free');
  });

  it('cancellation downgrades to free', async () => {
    const { send, rows } = make(row());
    await send(subEvent('evt_4'));
    await send({ ...subEvent('evt_5'), type: 'customer.subscription.deleted' });
    expect(rows.t1).toMatchObject({ plan: 'free', stripeSubscriptionId: null });
  });

  it('a late delete for an old subscription does not cancel the new one', async () => {
    const { send, rows } = make(row());
    await send(subEvent('evt_6', { id: 'sub_new' }));
    await send({
      ...subEvent('evt_7', { id: 'sub_old', status: 'canceled' }),
      type: 'customer.subscription.deleted',
    });
    expect(rows.t1).toMatchObject({
      plan: 'pro',
      stripeSubscriptionId: 'sub_new',
    });
  });

  it('a subscription with an unknown price (the retired $9 one) changes nothing', async () => {
    const { send, rows } = make(row());
    await send(
      subEvent('evt_old', { items: { data: [item('price_old_pro_9')] } }),
    );
    expect(rows.t1!.plan).toBe('free');
  });

  it('invoice events derive status from the live subscription', async () => {
    const { send, rows, setLive } = make(row());
    await send(subEvent('evt_8'));
    const live = subEvent('x').data.object;
    setLive({ ...live, status: 'past_due' });
    await send({
      id: 'evt_10',
      type: 'invoice.payment_failed',
      data: { object: { id: 'in_1', customer: 'cus_1' } },
    });
    expect(rows.t1!.status).toBe('past_due');
    setLive(live);
    await send({
      id: 'evt_11',
      type: 'invoice.paid',
      data: { object: { id: 'in_1', customer: 'cus_1' } },
    });
    expect(rows.t1!.status).toBe('active');
  });

  it('Pro yearly gets its monthly extra-device item added once', async () => {
    const { send, rows, stripe } = make(row());
    await send(
      subEvent('evt_y', { items: { data: [item(PRICE.PRO_YEARLY)] } }),
    );
    expect(rows.t1).toMatchObject({ plan: 'pro', billingInterval: 'year' });
    expect(stripe.subscriptionItems.create).toHaveBeenCalledWith(
      {
        subscription: 'sub_1',
        price: 'price_extra',
        proration_behavior: 'none',
      },
      { idempotencyKey: 'manar-usage-item-sub_1' },
    );
    await send(
      subEvent('evt_y2', {
        items: {
          data: [item(PRICE.PRO_YEARLY), item(PRICE.PRO_EXTRA_DEVICE)],
        },
      }),
    );
    expect(stripe.subscriptionItems.create).toHaveBeenCalledTimes(1);
  });

  it('Company yearly records committed seats (at least 3) and adds the monthly seat item', async () => {
    const { send, rows, stripe } = make(row());
    await send(
      subEvent('evt_cy', {
        items: { data: [item(PRICE.COMPANY_SEAT_YEARLY, 2)] },
      }),
    );
    expect(rows.t1).toMatchObject({ plan: 'company', committedSeats: 3 });
    expect(stripe.subscriptionItems.create).toHaveBeenCalledWith(
      expect.objectContaining({ price: 'price_seat_m' }),
      expect.anything(),
    );
  });

  it('a trialing Company subscription is a company trial, claimed with its card', async () => {
    const { send, rows, claims } = make(row());
    await send(
      subEvent('evt_tr', {
        status: 'trialing',
        trial_end: 1_900_000_000,
        default_payment_method: 'pm_a',
        items: { data: [item(PRICE.COMPANY_SEAT_MONTHLY)] },
      }),
    );
    expect(rows.t1).toMatchObject({
      plan: 'company_trial',
      trialEndsAt: new Date(1_900_000_000_000),
    });
    expect(claims[0]).toMatchObject({
      kind: 'company',
      cardFingerprint: 'fp_pm_a',
    });
  });

  it('a card that already had a company trial cancels the second trial at once', async () => {
    const { send, rows, stripe } = make(row());
    await send(
      subEvent('evt_a', {
        customer: 'cus_2',
        metadata: { tenantId: 't2' },
        status: 'trialing',
        default_payment_method: 'pm_same',
        items: { data: [item(PRICE.COMPANY_SEAT_MONTHLY)] },
      }),
    );
    await send(
      subEvent('evt_b', {
        status: 'trialing',
        default_payment_method: 'pm_same',
        items: { data: [item(PRICE.COMPANY_SEAT_MONTHLY)] },
      }),
    );
    expect(stripe.subscriptions.cancel).toHaveBeenCalledWith('sub_1');
    expect(rows.t1).toMatchObject({ plan: 'free', stripeSubscriptionId: null });
    expect(rows.t1!.trialEndsAt).toBeInstanceOf(Date);
  });

  it('a paid credit-pack Checkout adds credits from the paid line items, not metadata', async () => {
    const { send, wallet } = make(row());
    await send({
      id: 'evt_c',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_1',
          mode: 'payment',
          payment_status: 'paid',
          payment_intent: 'pi_cs_1',
          customer: 'cus_1',
          metadata: { tenantId: 't1', credits: '999999' },
        },
      },
    });
    expect(wallet.addPaidLot).toHaveBeenCalledWith(
      't1',
      'cs_1',
      'purchase',
      [{ lookupKey: PRICE.CREDITS_1000, quantity: 3 }],
      expect.any(Date),
      ['pi_cs_1'],
    );
  });

  it('an unpaid credit Checkout adds nothing', async () => {
    const { send, wallet } = make(row());
    await send({
      id: 'evt_u',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_2',
          mode: 'payment',
          payment_status: 'unpaid',
          customer: 'cus_1',
        },
      },
    });
    expect(wallet.addPaidLot).not.toHaveBeenCalled();
  });

  it('a paid auto top-up invoice adds a top_up lot from the live invoice lines', async () => {
    const { send, wallet, sub, stripe } = make(row());
    await send({
      id: 'evt_t',
      type: 'invoice.paid',
      data: {
        object: {
          id: 'in_top',
          customer: 'cus_1',
          metadata: { purpose: 'credit_top_up', tenantId: 't1' },
        },
      },
    });
    expect(wallet.addPaidLot).toHaveBeenCalledWith(
      't1',
      'in_top',
      'top_up',
      [{ lookupKey: PRICE.CREDITS_1000, quantity: 2 }],
      expect.any(Date),
      ['pi_top', 'ch_top', 'pi_top2'],
    );
    // The payments are only there when expanded.
    expect(stripe.invoices.retrieve).toHaveBeenCalledWith('in_top', {
      expand: ['payments'],
    });
    expect(sub).not.toHaveBeenCalled();
  });

  const disputeEvent = (
    id: string,
    type: string,
    d: { id: string; charge: string; status: string },
  ) => ({ id, type, data: { object: d } });

  it('a dispute freezes paid features; winning it restores them', async () => {
    const { send, rows, audit, disputes } = make(row());
    await send(subEvent('evt_p'));
    disputes.push({ id: 'dp_1', charge: 'ch_1', status: 'needs_response' });
    await send(disputeEvent('evt_d1', 'charge.dispute.created', disputes[0]!));
    expect(rows.t1).toMatchObject({ plan: 'pro', status: 'frozen' });
    expect(audit.recordSafely).toHaveBeenCalledWith(
      expect.anything(),
      't1',
      expect.objectContaining({ eventType: 'billing.dispute.changed' }),
    );
    // A subscription update while frozen keeps it frozen.
    await send(subEvent('evt_p2'));
    expect(rows.t1!.status).toBe('frozen');
    disputes[0]!.status = 'won';
    await send(disputeEvent('evt_d2', 'charge.dispute.closed', disputes[0]!));
    expect(rows.t1!.status).toBe('active');
  });

  it('state comes from all disputes in Stripe, not the event: a late "won" for one cannot unfreeze another open one', async () => {
    const { send, rows, disputes } = make(row());
    await send(subEvent('evt_s'));
    disputes.push(
      { id: 'dp_a', charge: 'ch_a', status: 'won' },
      { id: 'dp_b', charge: 'ch_b', status: 'under_review' },
    );
    await send(disputeEvent('evt_x', 'charge.dispute.closed', disputes[0]!));
    expect(rows.t1!.status).toBe('frozen');
    // Out of order: an old "created" event arrives after everything was won.
    disputes[1]!.status = 'won';
    await send(
      disputeEvent('evt_y', 'charge.dispute.created', {
        id: 'dp_b',
        charge: 'ch_b',
        status: 'needs_response',
      }),
    );
    expect(rows.t1!.status).toBe('active');
  });

  it('a lost dispute keeps paid features frozen and takes back the credits that charge bought', async () => {
    const { send, rows, disputes, wallet } = make(row());
    await send(subEvent('evt_l'));
    disputes.push({ id: 'dp_l', charge: 'ch_l', status: 'lost' });
    await send(disputeEvent('evt_l1', 'charge.dispute.closed', disputes[0]!));
    expect(rows.t1!.status).toBe('frozen');
    expect(wallet.revokeForPayment).toHaveBeenCalledWith(
      't1',
      ['ch_l', 'pi_ch_l', 'in_paid'],
      1,
    );
  });

  it('a refund takes back the unspent credits in proportion (partial refunds too)', async () => {
    const { send, wallet } = make(row());
    await send({
      id: 'evt_r',
      type: 'charge.refunded',
      data: {
        object: {
          id: 'ch_r',
          customer: 'cus_1',
          payment_intent: 'pi_r',
          amount: 1000,
          amount_refunded: 250,
        },
      },
    });
    // By the charge, its payment intent and the invoice it paid (a top-up).
    expect(wallet.revokeForPayment).toHaveBeenCalledWith(
      't1',
      ['ch_r', 'pi_r', 'in_paid'],
      0.25,
    );
  });

  it('a paid top-up with no payment link still adds the lot (keyed by invoice) and logs loudly', async () => {
    const { send, wallet, stripe, svc } = make(row());
    stripe.invoices.retrieve.mockResolvedValueOnce({
      id: 'in_bare',
      status: 'paid',
      payments: { data: [] },
      lines: {
        data: [
          {
            pricing: { price_details: { price: 'price_credits' } },
            quantity: 2,
          },
        ],
      },
    });
    const error = vi.spyOn(
      (svc as unknown as { logger: { error: (m: string) => void } }).logger,
      'error',
    );
    await send({
      id: 'evt_bare',
      type: 'invoice.paid',
      data: {
        object: {
          id: 'in_bare',
          customer: 'cus_1',
          metadata: { purpose: 'credit_top_up' },
        },
      },
    });
    expect(wallet.addPaidLot).toHaveBeenCalledWith(
      't1',
      'in_bare',
      'top_up',
      expect.anything(),
      expect.any(Date),
      [],
    );
    expect(error).toHaveBeenCalledWith(
      expect.stringContaining('no payment link'),
    );
  });

  const trialSub = (o: Record<string, unknown>) =>
    subEvent('evt_t', {
      status: 'trialing',
      items: { data: [item(PRICE.COMPANY_SEAT_MONTHLY)] },
      ...o,
    });

  it("trial fingerprint falls back to the customer's default, then the setup intent", async () => {
    const a = make(row());
    a.customerDefaultPm.id = 'pm_cust';
    await a.send(trialSub({ default_payment_method: null }));
    expect(a.claims[0]).toMatchObject({ cardFingerprint: 'fp_pm_cust' });

    const b = make(row());
    await b.send(
      trialSub({
        default_payment_method: null,
        pending_setup_intent: 'seti_ok',
      }),
    );
    expect(b.claims[0]).toMatchObject({ cardFingerprint: 'fp_pm_from_seti' });
  });

  it('non-card methods are fingerprinted too', async () => {
    const f = make(row());
    f.pms.pm_bank = {
      type: 'us_bank_account',
      us_bank_account: { fingerprint: 'bank_fp' },
    };
    await f.send(trialSub({ default_payment_method: 'pm_bank' }));
    expect(f.claims[0]).toMatchObject({
      cardFingerprint: 'us_bank_account:bank_fp',
    });
  });

  it('a trial with no payment-method fingerprint at all is refused', async () => {
    const f = make(row());
    f.pms.pm_link = { type: 'link', link: {} };
    await f.send(trialSub({ default_payment_method: 'pm_link' }));
    expect(f.stripe.subscriptions.cancel).toHaveBeenCalledWith('sub_1');
    expect(f.rows.t1).toMatchObject({
      plan: 'free',
      stripeSubscriptionId: null,
    });
    expect(f.claims).toHaveLength(0);
  });
});
