import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { LicensePayload } from './license';

/**
 * Test helpers only: a keypair generated at run time (never committed) and a signer that builds
 * the same JWS as scripts/license-issue.mjs.
 */
export function testKeys(kid = 'test-kid'): {
  dir: string;
  kid: string;
  privateKey: KeyObject;
} {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const dir = mkdtempSync(join(tmpdir(), 'manar-license-'));
  writeFileSync(
    join(dir, `${kid}.pub`),
    publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  );
  return { dir, kid, privateKey };
}

const b64 = (o: unknown) =>
  Buffer.from(JSON.stringify(o)).toString('base64url');

export function signLicense(
  payload: unknown,
  privateKey: KeyObject,
  kid: string,
): string {
  const input = `${b64({ alg: 'EdDSA', kid, typ: 'JWT' })}.${b64(payload)}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

export const NOW = new Date('2026-10-25T12:00:00Z');
const nowSec = NOW.getTime() / 1000;
export const DAY = 86_400;

export function payload(over: Partial<LicensePayload> = {}): LicensePayload {
  return {
    v: 1,
    lic: 'LIC-TEST-1',
    sub: 'Test customer',
    deployment: 'customer',
    iat: nowSec - 10 * DAY,
    nbf: nowSec - 10 * DAY,
    exp: nowSec + 200 * DAY,
    limits: { agents: 10, tenants: 1 },
    features: ['packs'],
    ...over,
  };
}
