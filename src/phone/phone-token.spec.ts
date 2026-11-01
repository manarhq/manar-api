import { describe, expect, it } from 'vitest';
import {
  signPushAction,
  signTelegramCallback,
  verifyPushAction,
  verifyTelegramCallback,
} from './phone-token';

const S = 'unit-test-signing-secret-0123456789';
const ID = '3f2b1c9e-8d7a-4b6c-9e5d-1a2b3c4d5e6f';

describe('push action token', () => {
  const claims = { a: ID, s: 'sub-1', t: 'tenant-1', e: Date.now() + 60_000 };
  it('round-trips', () => {
    const { token } = signPushAction(S, claims);
    expect(verifyPushAction(S, token)).toMatchObject(claims);
  });
  it('refuses a wrong secret, a tampered body, an expired token and junk', () => {
    const { token } = signPushAction(S, claims);
    expect(
      verifyPushAction('another-secret-another-secret-00', token),
    ).toBeNull();
    const [body, sig] = token.split('.');
    const forged = Buffer.from(
      JSON.stringify({ ...claims, s: 'sub-2', n: 'x' }),
    ).toString('base64url');
    expect(verifyPushAction(S, `${forged}.${sig}`)).toBeNull();
    expect(body).toBeTruthy();
    expect(verifyPushAction(S, token, claims.e + 1)).toBeNull();
    for (const j of ['', 'a', 'a.b', 'a.b.c', '.'])
      expect(verifyPushAction(S, j)).toBeNull();
  });
  it('is unique per token', () => {
    expect(signPushAction(S, claims).nonce).not.toBe(
      signPushAction(S, claims).nonce,
    );
  });
});

describe('telegram callback data', () => {
  it('fits in 64 bytes and verifies for the same chat only', () => {
    const d = signTelegramCallback(S, ID, 'y', '12345');
    expect(Buffer.byteLength(d)).toBeLessThanOrEqual(64);
    expect(verifyTelegramCallback(S, d, '12345')).toEqual({
      approvalId: ID,
      choice: 'y',
    });
    expect(verifyTelegramCallback(S, d, '99999')).toBeNull();
  });
  it('cannot flip the choice or swap the approval', () => {
    const d = signTelegramCallback(S, ID, 'y', '12345');
    expect(
      verifyTelegramCallback(S, d.replace('.y.', '.n.'), '12345'),
    ).toBeNull();
    expect(
      verifyTelegramCallback(S, d.replace('3f2b', '4f2b'), '12345'),
    ).toBeNull();
    expect(
      verifyTelegramCallback('another-secret-another-secret-00', d, '12345'),
    ).toBeNull();
    expect(verifyTelegramCallback(S, 'x'.repeat(64), '12345')).toBeNull();
  });
});
