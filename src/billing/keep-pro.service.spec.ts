/* eslint-disable @typescript-eslint/no-unsafe-assignment -- vitest asymmetric matchers are typed any */
import { describe, expect, it, vi } from 'vitest';
import { KeepProService } from './keep-pro.service';

const CLAIM = { stripeSubscriptionId: 'sub_1', keptAt: null as Date | null };

function make(
  opts: {
    customerAddress?: { country: string } | null;
    intentStatus?: string;
  } = {},
) {
  const calls: string[] = [];
  const update = vi.fn(() => Promise.resolve());
  const subUpdate = vi.fn(() => Promise.resolve());
  const create = vi.fn((...[,]: [Record<string, unknown>]) =>
    Promise.resolve({ url: 'https://stripe.example/setup' }),
  );
  const client = {
    checkout: { sessions: { create } },
    setupIntents: {
      retrieve: () =>
        Promise.resolve({
          status: opts.intentStatus ?? 'succeeded',
          payment_method: 'pm_1',
        }),
    },
    paymentMethods: {
      retrieve: () =>
        Promise.resolve({
          billing_details: {
            address: { country: 'AE', city: 'Dubai', line1: 'x' },
          },
        }),
    },
    customers: {
      retrieve: () =>
        Promise.resolve({ id: 'cus_1', address: opts.customerAddress ?? null }),
      update,
    },
    subscriptions: { update: subUpdate },
  };
  const claimUpdate = vi.fn(() => Promise.resolve());
  const control = {
    launchOfferClaim: {
      findUnique: () => Promise.resolve({ ...CLAIM }),
      update: claimUpdate,
    },
    tenantEntitlement: {
      findUnique: () => Promise.resolve({ stripeCustomerId: 'cus_1' }),
    },
  };
  const svc = new KeepProService(
    control as never,
    { client: () => client } as never,
    { upgradeUrl: () => 'https://c.example/settings/billing' } as never,
  );
  return { svc, create, update, subUpdate, claimUpdate, calls };
}

const session = (over: Record<string, unknown> = {}) =>
  ({
    mode: 'setup',
    customer: 'cus_1',
    setup_intent: 'seti_1',
    metadata: { tenantId: 't1', purpose: 'keep_pro', subscriptionId: 'sub_1' },
    ...over,
  }) as never;

describe('KeepProService', () => {
  it('opens a setup-mode Checkout that collects card, address and tax id', async () => {
    const { svc, create } = make();
    expect(await svc.createSession('t1')).toEqual({
      url: 'https://stripe.example/setup',
    });
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        mode: 'setup',
        customer: 'cus_1',
        billing_address_collection: 'required',
        tax_id_collection: { enabled: true },
        metadata: expect.objectContaining({
          purpose: 'keep_pro',
          subscriptionId: 'sub_1',
        }),
      }),
    );
  });

  it('retries without tax id collection when setup mode refuses it', async () => {
    const { svc, create } = make();
    create
      .mockRejectedValueOnce(
        Object.assign(new Error('tax_id_collection not supported'), {
          type: 'StripeInvalidRequestError',
        }),
      )
      .mockResolvedValueOnce({ url: 'https://stripe.example/setup2' });
    expect((await svc.createSession('t1')).url).toBe(
      'https://stripe.example/setup2',
    );
    expect(create.mock.calls[1]![0]).not.toHaveProperty('tax_id_collection');
  });

  it('on completion sets the default card and turns automatic tax on', async () => {
    const { svc, subUpdate, update, claimUpdate } = make();
    await svc.complete('t1', session());
    expect(subUpdate).toHaveBeenCalledWith('sub_1', {
      default_payment_method: 'pm_1',
      automatic_tax: { enabled: true },
    });
    expect(update).toHaveBeenCalledWith('cus_1', {
      invoice_settings: { default_payment_method: 'pm_1' },
    });
    // no address on the customer: copied from the card so tax can be computed
    expect(update).toHaveBeenCalledWith(
      'cus_1',
      expect.objectContaining({
        address: expect.objectContaining({ country: 'AE' }),
      }),
    );
    expect(claimUpdate).toHaveBeenCalled();
  });

  it('keeps an address Checkout already saved', async () => {
    const { svc, update } = make({ customerAddress: { country: 'AE' } });
    await svc.complete('t1', session());
    expect(update).not.toHaveBeenCalledWith(
      'cus_1',
      expect.objectContaining({ address: expect.anything() }),
    );
  });

  it('ignores other purposes, a different subscription and an unfinished setup', async () => {
    for (const s of [
      session({ metadata: { purpose: 'other' } }),
      session({
        metadata: { purpose: 'keep_pro', subscriptionId: 'sub_other' },
      }),
      session({ mode: 'subscription' }),
    ]) {
      const m = make();
      await m.svc.complete('t1', s);
      expect(m.subUpdate).not.toHaveBeenCalled();
    }
    const m = make({ intentStatus: 'requires_action' });
    await m.svc.complete('t1', session());
    expect(m.subUpdate).not.toHaveBeenCalled();
  });
});
