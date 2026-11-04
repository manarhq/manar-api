import { UnauthorizedException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import {
  GrowthIdentityController,
  GrowthPublicController,
  GrowthWorkspaceController,
} from './growth.controller';
import { signToken } from './signed-token';

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

describe('unsubscribe', () => {
  const make = () => {
    const unsubscribe = vi.fn(() => Promise.resolve(true));
    const c = new GrowthPublicController(
      {} as never,
      { unsubscribe } as never,
      { get: () => 's'.repeat(32) } as never,
    );
    return { c, unsubscribe };
  };
  it('a GET (scanner, preview) changes nothing and shows a POST button', () => {
    const { c, unsubscribe } = make();
    const html = c.unsubscribeGet('abc.def');
    expect(html).toContain('<form method="post"');
    expect(unsubscribe).not.toHaveBeenCalled();
  });
  it('the POST with a valid token unsubscribes; a forged one does not', async () => {
    const { c, unsubscribe } = make();
    await c.unsubscribePost(
      signToken('s'.repeat(32), 'unsubscribe', 'm1', null),
    );
    expect(unsubscribe).toHaveBeenCalledWith('m1');
    await expect(c.unsubscribePost('forged.token')).rejects.toThrow(
      'invalid_link',
    );
  });
});

describe('invite emails', () => {
  it('are capped per workspace: 20 an hour (each invite, and each replacement, is an email)', () => {
    const handler = Object.getOwnPropertyDescriptor(
      GrowthWorkspaceController.prototype,
      'invite',
    )!.value as object;
    expect(Reflect.getMetadata('THROTTLER:LIMIThuman', handler)).toBe(20);
    expect(Reflect.getMetadata('THROTTLER:TTLhuman', handler)).toBe(3_600_000);
  });
});
