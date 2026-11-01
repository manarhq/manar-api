import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * `base64url(json).base64url(hmac)`: a purpose-bound, expiring link token. The purpose is inside
 * the signed bytes, so an unsubscribe token can never be replayed as an invite. Single use is the
 * caller's job (a database row), not the token's.
 */
export type TokenPurpose = 'invite' | 'unsubscribe';

export function signToken(
  secret: string,
  purpose: TokenPurpose,
  subject: string,
  expiresAt: Date | null,
): string {
  const body = Buffer.from(
    JSON.stringify({ p: purpose, s: subject, e: expiresAt?.getTime() ?? 0 }),
  ).toString('base64url');
  return `${body}.${mac(secret, body)}`;
}

/** The signed subject, or null when the signature, purpose or expiry do not hold. */
export function verifyToken(
  secret: string,
  purpose: TokenPurpose,
  token: string,
  now = new Date(),
): string | null {
  const [body, sig, extra] = token.split('.');
  if (!body || !sig || extra !== undefined) return null;
  const want = Buffer.from(mac(secret, body));
  const got = Buffer.from(sig);
  if (want.length !== got.length || !timingSafeEqual(want, got)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString()) as {
      p?: unknown;
      s?: unknown;
      e?: unknown;
    };
    if (p.p !== purpose || typeof p.s !== 'string' || typeof p.e !== 'number')
      return null;
    if (p.e !== 0 && p.e <= now.getTime()) return null;
    return p.s;
  } catch {
    return null;
  }
}

const mac = (secret: string, body: string) =>
  createHmac('sha256', secret).update(body).digest('base64url');
