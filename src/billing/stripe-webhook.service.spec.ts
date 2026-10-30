import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { CompanyQuantityService } from './company-quantity.service';
import { EntitlementsService } from './entitlements.service';
import { StripeWebhookService } from './stripe-webhook.service';

const PRICES: Record<string, string> = {
  PRO_MONTHLY: 'price_pm',
  PRO_YEARLY: 'price_py',
  COMPANY_USER: 'price_cu',
  EXTRA_DEVICE: 'price_ed',
};

function make(rows: Record<string, Record<string, unknown>>) {
  const events = new Set<string>();
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
      create: vi.fn(({ data }: { data: { id: string } }) => {
        if (events.has(data.id))
          return Promise.reject(
            Object.assign(new Error('dup'), { code: 'P2002' }),
          );
        events.add(data.id);
        return Promise.resolve();
      }),
      delete: vi.fn(({ where }: { where: { id: string } }) => {
        events.delete(where.id);
        return Promise.resolve();
      }),
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
  const gateway = {
    constructEvent: vi.fn(() => {
      if (next === 'bad') throw new Error('bad signature');
      return next;
    }),
    price: (n: string) => PRICES[n],
    client: () => ({ subscriptions: { retrieve: sub } }),
  };
  const svc = new StripeWebhookService(
    control as never,
    entitlements,
    gateway as never,
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
    sub,
    setLive: (v: unknown) => (live = v),
  };
}

const subEvent = (id: string, o: Record<string, unknown> = {}) => ({
  id,
  type: 'customer.subscription.updated',
  created: 1_800_000_000,
  data: {
    object: {
      id: 'sub_1',
      customer: 'cus_1',
      status: 'active',
      metadata: { tenantId: 't1' },
      items: { data: [{ price: { id: 'price_pm' } }] },
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

  it('applies a subscription once; a duplicate delivery is ignored', async () => {
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

  it('cancellation downgrades to free and keeps nothing else', async () => {
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

  const inv = (id: string, type: string) => ({
    id,
    type,
    created: 1_800_000_100,
    data: { object: { id: 'in_1', customer: 'cus_1' } },
  });
  const liveSub = (o: Record<string, unknown> = {}) => ({
    id: 'sub_1',
    customer: 'cus_1',
    status: 'active',
    items: { data: [{ price: { id: 'price_pm' } }] },
    ...o,
  });

  it('invoice events derive status from the live subscription', async () => {
    const { send, rows, setLive } = make(row());
    await send(subEvent('evt_8'));
    setLive(liveSub({ status: 'past_due' }));
    await send(inv('evt_9', 'invoice.payment_failed'));
    expect(rows.t1!.status).toBe('past_due');
    setLive(liveSub());
    await send(inv('evt_10', 'invoice.paid'));
    expect(rows.t1!.status).toBe('active');
  });

  it('a late payment_failed cannot overwrite a newer paid state', async () => {
    const { send, rows, setLive } = make(row());
    await send(subEvent('evt_8'));
    setLive(liveSub()); // Stripe already says paid and active
    await send(inv('evt_11', 'invoice.payment_failed'));
    expect(rows.t1!.status).toBe('active');
  });

  it('an invoice event does not drop a later-delivered plan change', async () => {
    const { send, rows } = make(row());
    await send(subEvent('evt_8'));
    await send(inv('evt_12', 'invoice.paid')); // newer timestamp than the update below
    await send({
      ...subEvent('evt_13', {
        items: { data: [{ price: { id: 'price_py' } }] },
      }),
      created: 1_700_000_000,
    });
    expect(rows.t1).toMatchObject({ plan: 'pro', billingInterval: 'year' });
  });

  it('the Company price makes a company plan', async () => {
    const { send, rows } = make(row());
    await send(
      subEvent('evt_11', { items: { data: [{ price: { id: 'price_cu' } }] } }),
    );
    expect(rows.t1!.plan).toBe('company');
  });
});

describe('CompanyQuantityService', () => {
  const PERIOD = 1_790_000_000;
  function quantity(
    items: { id: string; price: string; quantity: number }[],
    billed: { users: number; extraDevices: number },
  ) {
    const update = vi.fn(() => Promise.resolve());
    const create = vi.fn(() => Promise.resolve());
    const billable = vi.fn(() => Promise.resolve(billed));
    const svc = new CompanyQuantityService(
      {} as never,
      { billable } as never,
      {
        price: (n: string) => PRICES[n],
        client: () => ({
          subscriptions: {
            retrieve: () =>
              Promise.resolve({
                items: {
                  data: items.map((i) => ({
                    id: i.id,
                    price: { id: i.price },
                    quantity: i.quantity,
                    current_period_start: PERIOD,
                  })),
                },
              }),
          },
          subscriptionItems: { update, create },
        }),
      } as never,
    );
    return { svc, update, create, billable };
  }

  it('raises with prorations, creates the device item, and counts from the period start', async () => {
    const { svc, update, create, billable } = quantity(
      [{ id: 'si_u', price: 'price_cu', quantity: 1 }],
      { users: 4, extraDevices: 2 },
    );
    await svc.syncTenant('t1', 'sub_1');
    expect(billable).toHaveBeenCalledWith('t1', new Date(PERIOD * 1000));
    expect(update).toHaveBeenCalledWith('si_u', {
      quantity: 4,
      proration_behavior: 'create_prorations',
    });
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ price: 'price_ed', quantity: 2 }),
    );
  });

  it('applies decreases unprorated, at renewal', async () => {
    const { svc, update } = quantity(
      [
        { id: 'si_u', price: 'price_cu', quantity: 5 },
        { id: 'si_d', price: 'price_ed', quantity: 4 },
      ],
      { users: 3, extraDevices: 1 },
    );
    await svc.syncTenant('t1', 'sub_1');
    expect(update).toHaveBeenCalledWith('si_u', {
      quantity: 3,
      proration_behavior: 'none',
    });
    expect(update).toHaveBeenCalledWith('si_d', {
      quantity: 1,
      proration_behavior: 'none',
    });
  });

  it('a failing round is logged and does not crash the worker', async () => {
    vi.useFakeTimers();
    const findMany = vi.fn(() => Promise.reject(new Error('db down')));
    const svc = new CompanyQuantityService(
      { tenantEntitlement: { findMany } } as never,
      {} as never,
      { configured: true } as never,
    );
    const unhandled = vi.fn();
    process.on('unhandledRejection', unhandled);
    svc.onModuleInit();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(findMany).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(24 * 3600 * 1000); // and it still runs the next day
    expect(findMany).toHaveBeenCalledTimes(2);
    expect(unhandled).not.toHaveBeenCalled();
    process.off('unhandledRejection', unhandled);
    svc.onModuleDestroy();
    vi.useRealTimers();
  });
});
