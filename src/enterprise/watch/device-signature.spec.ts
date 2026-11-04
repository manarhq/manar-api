import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonical,
  isP256PublicJwk,
  thumbprint,
  verifyDeviceSignature,
} from './device-signature';

const { publicKey, privateKey } = generateKeyPairSync('ec', {
  namedCurve: 'P-256',
});
const jwk = publicKey.export({ format: 'jwk' });
const NOW = 1_793_778_000_000;
const signed = (method: string, path: string, time: number, body: string) =>
  sign('sha256', Buffer.from(canonical(method, path, time, body)), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');

describe('device signatures (R11)', () => {
  const body = '{"events":[]}';
  const sig = signed('POST', '/watch/v1/events', NOW, body);
  const base = {
    jwk,
    method: 'POST',
    path: '/watch/v1/events',
    time: String(NOW),
    now: NOW,
    body,
    signature: sig,
  };

  it('matches what the extension signs', () => {
    expect(canonical('post', '/watch/v1/events', NOW, '{"a":1}')).toBe(
      'POST\n/watch/v1/events\n1793778000000\n015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862',
    );
  });
  it('accepts a correct signature', () => {
    expect(verifyDeviceSignature(base)).toBe(true);
  });
  it('refuses another path, a changed body, another method, a missing signature', () => {
    expect(
      verifyDeviceSignature({ ...base, path: '/watch/v1/heartbeat' }),
    ).toBe(false);
    expect(verifyDeviceSignature({ ...base, body: '{"events":[1]}' })).toBe(
      false,
    );
    expect(verifyDeviceSignature({ ...base, method: 'GET' })).toBe(false);
    expect(verifyDeviceSignature({ ...base, signature: undefined })).toBe(
      false,
    );
    expect(verifyDeviceSignature({ ...base, signature: 'x'.repeat(86) })).toBe(
      false,
    );
  });
  it('refuses a time outside 120 s, and a malformed time', () => {
    expect(verifyDeviceSignature({ ...base, now: NOW + 120_001 })).toBe(false);
    expect(verifyDeviceSignature({ ...base, now: NOW - 120_001 })).toBe(false);
    expect(verifyDeviceSignature({ ...base, now: NOW + 119_000 })).toBe(true);
    expect(verifyDeviceSignature({ ...base, time: '1e12' })).toBe(false);
  });
  it('refuses another key', () => {
    const other = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    }).publicKey.export({ format: 'jwk' });
    expect(verifyDeviceSignature({ ...base, jwk: other })).toBe(false);
  });
  it('accepts only public P-256 keys', () => {
    expect(isP256PublicJwk(jwk)).toBe(true);
    expect(isP256PublicJwk(privateKey.export({ format: 'jwk' }))).toBe(false);
    expect(isP256PublicJwk({ ...jwk, crv: 'P-384' })).toBe(false);
    expect(isP256PublicJwk({ kty: 'RSA' })).toBe(false);
    expect(isP256PublicJwk(null)).toBe(false);
  });
  it('the thumbprint ignores member order and extra members', () => {
    expect(
      thumbprint({
        y: jwk.y,
        x: jwk.x,
        crv: 'P-256',
        kty: 'EC',
        ext: true,
      }),
    ).toBe(thumbprint(jwk));
  });
});
