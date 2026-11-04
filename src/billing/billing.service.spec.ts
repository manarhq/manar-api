import { ConflictException, ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { BillingService } from './billing.service';

function make(
  subs: { status: string }[],
  open: { id: string }[] = [],
  opts: {
    kind?: 'PERSONAL' | 'COMPANY';
    row?: Record<string, unknown>;
    claimed?: boolean;
    plan?: string;
    status?: string;
    live?: Record<string, unknown>;
  } = {},
) {
  const expire = vi.fn(() => Promise.resolve());
  const create = vi.fn((params: unknown) => {
    void params;
    return Promise.resolve({ url: 'https://stripe.example/c' });
  });
  const cancel = vi.fn(() => Promise.resolve({}));
  const client = {
    subscriptions: {
      list: () => Promise.resolve({ data: subs }),
      retrieve: () => Promise.resolve(opts.live),
      cancel,
    },
    checkout: {
      sessions: {
        list: () => ({
          // eslint-disable-next-line @typescript-eslint/require-await
          async *[Symbol.asyncIterator]() {
            yield* open;
          },
        }),
        expire,
        create,
      },
    },
  };
  const svc = new BillingService(
    {
      tenantEntitlement: {
        findUnique: () =>
          Promise.resolve({
            tenantId: 't1',
            stripeCustomerId: 'cus_1',
            ...opts.row,
          }),
      },
      tenant: {
        findUnique: () =>
          Promise.resolve({ id: 't1', kind: opts.kind ?? 'PERSONAL' }),
      },
      trialClaim: {
        findFirst: () => Promise.resolve(opts.claimed ? { id: 'c' } : null),
      },
    } as never,
    {
      upgradeUrl: () => 'https://c.example/settings/billing',
      get: () =>
        Promise.resolve({
          plan: opts.plan ?? 'pro',
          status: opts.status ?? 'active',
        }),
    } as never,
    {} as never,
    {
      client: () => client,
      price: (k: string) => Promise.resolve(`id_${k}`),
    } as never,
  );
  const params = () =>
    create.mock.calls[0]![0] as {
      mode: string;
      line_items: { price: string; quantity?: number }[];
      subscription_data?: Record<string, unknown>;
      automatic_tax: { enabled: boolean };
      payment_method_collection?: string;
    };
  return { svc, expire, create, params, cancel };
}

describe('BillingService.checkout', () => {
  it.each(['active', 'trialing', 'past_due', 'incomplete'])(
    'refuses with 409 when the customer already has a %s subscription',
    async (status) => {
      const { svc, create } = make([{ status }]);
      await expect(
        svc.checkout('t1', 'a@b.c', 'pro_monthly'),
      ).rejects.toBeInstanceOf(ConflictException);
      expect(create).not.toHaveBeenCalled();
    },
  );

  it('expires open checkout sessions, then creates one', async () => {
    const { svc, expire, create } = make(
      [{ status: 'canceled' }],
      [{ id: 'cs_1' }, { id: 'cs_2' }],
    );
    expect(await svc.checkout('t1', 'a@b.c', 'pro_monthly')).toEqual({
      url: 'https://stripe.example/c',
    });
    expect(expire).toHaveBeenCalledTimes(2);
    expect(create).toHaveBeenCalledTimes(1);
  });

  it('Pro monthly: $5 base plus the metered extra-device price, VAT by Stripe Tax', async () => {
    const { svc, params } = make([]);
    await svc.checkout('t1', 'a@b.c', 'pro_monthly');
    expect(params().line_items).toEqual([
      { price: 'id_manar_pro_monthly_v2', quantity: 1 },
      { price: 'id_manar_pro_extra_device_v2' },
    ]);
    expect(params().automatic_tax).toEqual({ enabled: true });
    expect(params().subscription_data).toMatchObject({
      billing_mode: { type: 'flexible' },
    });
  });

  it('Company yearly commits at least 3 seats', async () => {
    const { svc, params } = make([], [], { kind: 'COMPANY' });
    await svc.checkout('t1', 'a@acme.io', 'company_yearly', 2);
    expect(params().line_items).toEqual([
      { price: 'id_manar_company_seat_yearly_v2', quantity: 3 },
    ]);
  });

  it('a plan must match the workspace: no Pro for a company, no Company for a person', async () => {
    await expect(
      make([], [], { kind: 'COMPANY' }).svc.checkout(
        't1',
        'a@b.c',
        'pro_monthly',
      ),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(
      make([]).svc.checkout('t1', 'a@b.c', 'company_monthly'),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('company trial: card collected, 14 days, and only for a work email', async () => {
    const ok = make([], [], { kind: 'COMPANY' });
    await ok.svc.checkout('t1', 'it@acme.io', 'company_trial');
    expect(ok.params().payment_method_collection).toBe('always');
    expect(ok.params().subscription_data).toMatchObject({
      trial_period_days: 14,
      trial_settings: { end_behavior: { missing_payment_method: 'cancel' } },
    });
    for (const email of ['me@gmail.com', 'x@mailinator.com'])
      await expect(
        make([], [], { kind: 'COMPANY' }).svc.checkout(
          't1',
          email,
          'company_trial',
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('company trial: once per workspace', async () => {
    await expect(
      make([], [], {
        kind: 'COMPANY',
        row: { trialEndsAt: new Date() },
      }).svc.checkout('t1', 'it@acme.io', 'company_trial'),
    ).rejects.toBeInstanceOf(ConflictException);
    await expect(
      make([], [], { kind: 'COMPANY', claimed: true }).svc.checkout(
        't1',
        'it@acme.io',
        'company_trial',
      ),
    ).rejects.toBeInstanceOf(ConflictException);
  });
});

describe('BillingService.buyCredits', () => {
  it('one-time Checkout with a tax invoice and an adjustable pack count', async () => {
    const { svc, params } = make([]);
    await svc.buyCredits('t1', 'a@b.c', 2);
    const p = params() as unknown as {
      mode: string;
      line_items: Record<string, unknown>[];
      invoice_creation: { enabled: boolean };
    };
    expect(p.mode).toBe('payment');
    expect(p.invoice_creation.enabled).toBe(true);
    expect(p.line_items[0]).toMatchObject({
      price: 'id_manar_credits_1000_v2',
      quantity: 2,
      adjustable_quantity: { enabled: true, minimum: 1, maximum: 20 },
    });
  });

  it('Free and trial workspaces may buy packs; a frozen or read-only one cannot', async () => {
    for (const plan of ['free', 'trial'])
      await expect(
        make([], [], { plan }).svc.buyCredits('t1', 'a@b.c', 1),
      ).resolves.toEqual({ url: 'https://stripe.example/c' });
    for (const status of ['frozen', 'read_only'])
      await expect(
        make([], [], { status }).svc.buyCredits('t1', 'a@b.c', 1),
      ).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe('BillingService.cancelTrial', () => {
  it('cancels a trialing Company subscription at once (one click, nothing charged)', async () => {
    const { svc, cancel } = make([], [], {
      kind: 'COMPANY',
      row: { plan: 'company_trial', stripeSubscriptionId: 'sub_t' },
      live: { id: 'sub_t', status: 'trialing' },
    });
    expect(await svc.cancelTrial('t1')).toEqual({ cancelled: true });
    expect(cancel).toHaveBeenCalledWith('sub_t');
  });

  it('refuses when there is no trial, or it already converted', async () => {
    await expect(make([]).svc.cancelTrial('t1')).rejects.toMatchObject({
      status: 404,
    });
    await expect(
      make([], [], {
        row: { plan: 'company_trial', stripeSubscriptionId: 'sub_t' },
        live: { id: 'sub_t', status: 'active' },
      }).svc.cancelTrial('t1'),
    ).rejects.toBeInstanceOf(ConflictException);
  });
});
