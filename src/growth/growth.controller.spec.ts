import { UnauthorizedException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { GrowthIdentityController } from './growth.controller';

function make() {
  const request = vi.fn(() => Promise.resolve({ scheduled: true }));
  const c = new GrowthIdentityController(
    {} as never,
    { request } as never,
    {} as never,
    { verified: () => Promise.resolve('me@acme.io') } as never,
  );
  return { c, request };
}
const id = (authTime?: number) =>
  ({ issuer: 'i', subject: 'u', authTime }) as never;

describe('account deletion needs a fresh sign-in', () => {
  it('refuses a stale, missing or future-less auth_time with reauth_required (max age 300)', async () => {
    for (const t of [undefined, Date.now() / 1000 - 301]) {
      const { c, request } = make();
      await expect(c.requestDeletion(id(t))).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
      await c.requestDeletion(id(t)).catch((e: UnauthorizedException) =>
        expect(e.getResponse()).toMatchObject({
          code: 'reauth_required',
          maxAge: 300,
        }),
      );
      expect(request).not.toHaveBeenCalled();
    }
  });
  it('accepts a sign-in from the last five minutes and mails the verified address', async () => {
    const { c, request } = make();
    await c.requestDeletion(id(Date.now() / 1000 - 60));
    expect(request).toHaveBeenCalledWith('i', 'u', 'me@acme.io');
  });
});
