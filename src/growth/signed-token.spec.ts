import { describe, expect, it } from 'vitest';
import { signToken, verifyToken } from './signed-token';

const SECRET = 'x'.repeat(32);

describe('signed tokens', () => {
  it('round-trips and binds the purpose', () => {
    const t = signToken(SECRET, 'invite', 'abc', new Date(Date.now() + 1000));
    expect(verifyToken(SECRET, 'invite', t)).toBe('abc');
    expect(verifyToken(SECRET, 'unsubscribe', t)).toBeNull();
  });
  it('refuses expired, tampered and wrong-key tokens', () => {
    const t = signToken(SECRET, 'invite', 'abc', new Date(Date.now() - 1));
    expect(verifyToken(SECRET, 'invite', t)).toBeNull();
    const ok = signToken(SECRET, 'invite', 'abc', new Date(Date.now() + 5000));
    expect(verifyToken('y'.repeat(32), 'invite', ok)).toBeNull();
    const [b, s] = ok.split('.');
    const forged = Buffer.from(
      JSON.stringify({ p: 'invite', s: 'evil', e: Date.now() + 5000 }),
    ).toString('base64url');
    expect(verifyToken(SECRET, 'invite', `${forged}.${s}`)).toBeNull();
    expect(verifyToken(SECRET, 'invite', `${b}.${s}.x`)).toBeNull();
    expect(verifyToken(SECRET, 'invite', 'garbage')).toBeNull();
  });
  it('an unsubscribe token with no expiry never expires', () => {
    const t = signToken(SECRET, 'unsubscribe', 'm1', null);
    expect(verifyToken(SECRET, 'unsubscribe', t, new Date('2099-01-01'))).toBe(
      'm1',
    );
  });
});
