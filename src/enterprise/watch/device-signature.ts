import {
  createHash,
  createPublicKey,
  verify,
  type JsonWebKey,
} from 'node:crypto';

/** How far a device's clock may be from ours (R11). */
export const SIGNATURE_WINDOW_MS = 120_000;

/** METHOD\nPATH\nTIME\nsha256hex(body): what WATCH signs (manar-browser src/background/device-key.ts). */
export function canonical(
  method: string,
  path: string,
  time: number,
  body: Buffer | string,
): string {
  const digest = createHash('sha256').update(body).digest('hex');
  return `${method.toUpperCase()}\n${path}\n${time}\n${digest}`;
}

/** A public P-256 key only: anything else (a private key, another curve, extra members) is refused. */
export function isP256PublicJwk(jwk: unknown): jwk is JsonWebKey {
  if (!jwk || typeof jwk !== 'object') return false;
  const k = jwk as Record<string, unknown>;
  const b64 = /^[A-Za-z0-9_-]{43}$/;
  return (
    k.kty === 'EC' &&
    k.crv === 'P-256' &&
    typeof k.x === 'string' &&
    b64.test(k.x) &&
    typeof k.y === 'string' &&
    b64.test(k.y) &&
    k.d === undefined
  );
}

/** RFC 7638 thumbprint of a P-256 public key. */
export function thumbprint(jwk: JsonWebKey): string {
  const json = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
  return createHash('sha256').update(json).digest('base64url');
}

/**
 * Verifies one signed device request. False on any problem: a bad key, a time outside the window,
 * a malformed signature or a mismatch. Never throws.
 */
export function verifyDeviceSignature(input: {
  jwk: unknown;
  method: string;
  path: string;
  time: string | undefined;
  now: number;
  body: Buffer | string;
  signature: string | undefined;
}): boolean {
  try {
    if (!isP256PublicJwk(input.jwk)) return false;
    if (!input.time || !/^\d{13}$/.test(input.time)) return false;
    const time = Number(input.time);
    if (Math.abs(input.now - time) > SIGNATURE_WINDOW_MS) return false;
    if (!input.signature || !/^[A-Za-z0-9_-]{86}$/.test(input.signature))
      return false;
    const key = createPublicKey({ key: input.jwk, format: 'jwk' });
    return verify(
      'sha256',
      Buffer.from(canonical(input.method, input.path, time, input.body)),
      { key, dsaEncoding: 'ieee-p1363' },
      Buffer.from(input.signature, 'base64url'),
    );
  } catch {
    return false;
  }
}
