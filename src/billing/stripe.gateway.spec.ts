import { describe, expect, it } from 'vitest';
import { StripeGateway } from './stripe.gateway';

describe('StripeGateway client', () => {
  it('has a 20 s timeout and bounded network retries instead of the SDK defaults', () => {
    const gw = new StripeGateway({
      get: (k: string) => (k === 'STRIPE_SECRET_KEY' ? 'sk_test_x' : undefined),
    } as never);
    const c = gw.client() as unknown as {
      getApiField: (f: string) => unknown;
    };
    expect(c.getApiField('timeout')).toBe(20_000);
    expect(c.getApiField('maxNetworkRetries')).toBe(2);
  });
});
