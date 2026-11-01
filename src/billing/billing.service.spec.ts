import { ConflictException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { BillingService } from './billing.service';

function make(subs: { status: string }[], open: { id: string }[] = []) {
  const expire = vi.fn(() => Promise.resolve());
  const create = vi.fn(() =>
    Promise.resolve({ url: 'https://stripe.example/c' }),
  );
  const client = {
    subscriptions: { list: () => Promise.resolve({ data: subs }) },
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
          Promise.resolve({ tenantId: 't1', stripeCustomerId: 'cus_1' }),
      },
    } as never,
    { upgradeUrl: () => 'https://c.example/settings/billing' } as never,
    { billable: () => Promise.resolve({ users: 2, extraDevices: 0 }) } as never,
    { client: () => client, price: () => 'price_x' } as never,
  );
  return { svc, expire, create };
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
});
