import { ConflictException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { BillingController } from './billing.controller';

const auth = {
  issuer: 'i',
  tenant: { id: 't1' },
  user: { keycloakSubject: 'u', email: 'u@idp.invalid' },
} as never;

describe('POST /billing/checkout', () => {
  it('uses the verified contact email, never the token email', async () => {
    const checkout = vi.fn(() => Promise.resolve({ url: 'u' }));
    const c = new BillingController(
      { checkout } as never,
      {} as never,
      { verified: () => Promise.resolve('me@acme.io') } as never,
    );
    await c.checkout(auth, { plan: 'pro_monthly' });
    expect(checkout).toHaveBeenCalledWith(
      't1',
      'me@acme.io',
      'pro_monthly',
      undefined,
    );
  });

  it('answers 409 contact_email_required when there is none', async () => {
    const checkout = vi.fn();
    const c = new BillingController(
      { checkout } as never,
      {} as never,
      { verified: () => Promise.resolve(null) } as never,
    );
    await expect(
      c.checkout(auth, { plan: 'pro_monthly' }),
    ).rejects.toBeInstanceOf(ConflictException);
    expect(checkout).not.toHaveBeenCalled();
  });
});
