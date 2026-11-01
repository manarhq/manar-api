import { describe, expect, it } from 'vitest';
import {
  approvalMatchCode,
  linkCodeHash,
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

const B = { chatId: '12345', tenantId: 't1', subject: 'u1' };

describe('telegram callback data', () => {
  it('fits in 64 bytes and verifies for the same chat, workspace and person only', () => {
    const d = signTelegramCallback(S, ID, 'y', B);
    expect(Buffer.byteLength(d)).toBeLessThanOrEqual(64);
    expect(verifyTelegramCallback(S, d, B)).toEqual({
      approvalId: ID,
      choice: 'y',
    });
    expect(verifyTelegramCallback(S, d, { ...B, chatId: '99999' })).toBeNull();
    expect(verifyTelegramCallback(S, d, { ...B, tenantId: 't2' })).toBeNull();
    expect(verifyTelegramCallback(S, d, { ...B, subject: 'u2' })).toBeNull();
  });
  it('cannot flip the choice or swap the approval', () => {
    const d = signTelegramCallback(S, ID, 'y', B);
    expect(verifyTelegramCallback(S, d.replace('.y.', '.n.'), B)).toBeNull();
    expect(verifyTelegramCallback(S, d.replace('3f2b', '4f2b'), B)).toBeNull();
    expect(
      verifyTelegramCallback('another-secret-another-secret-00', d, B),
    ).toBeNull();
    expect(verifyTelegramCallback(S, 'x'.repeat(64), B)).toBeNull();
  });
});

describe('match code and link code hash', () => {
  it('match code is 4 characters from the id', () => {
    expect(approvalMatchCode(ID)).toBe('3F2B');
  });
  it('link code hash is keyed, ignores formatting, and differs per secret', () => {
    expect(linkCodeHash(S, 'abcd-2345')).toBe(linkCodeHash(S, 'ABCD2345'));
    expect(linkCodeHash(S, 'ABCD2345')).not.toBe(
      linkCodeHash('another-secret-another-secret-00', 'ABCD2345'),
    );
  });
});
