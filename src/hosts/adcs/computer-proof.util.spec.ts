import 'reflect-metadata';
import { createPrivateKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { webcrypto } from 'node:crypto';
import { makeCa, makeLeaf } from '../../../test/support/test-pki';
import { signProof, verifyProof } from './computer-proof.util';

const base = {
  tenantSlug: 'acme',
  machineId: 'pc01',
  csrKeyFingerprint: 'a'.repeat(64),
  timestamp: new Date().toISOString(),
};

async function setup() {
  const ca = await makeCa('Proof CA');
  const leaf = await makeLeaf(ca);
  const pkcs8 = Buffer.from(
    await webcrypto.subtle.exportKey('pkcs8', leaf.keys.privateKey),
  );
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  return { leaf, key };
}

describe('computer proof', () => {
  it('verifies a proof made by the certificate key', async () => {
    const { leaf, key } = await setup();
    expect(verifyProof(leaf.cert, base, signProof(key, base))).toBe(true);
  });

  it('refuses another key, machine, tenant, CSR key or stale time', async () => {
    const { leaf, key } = await setup();
    const sig = signProof(key, base);
    for (const changed of [
      { machineId: 'pc02' },
      { tenantSlug: 'evil' },
      { csrKeyFingerprint: 'b'.repeat(64) },
      { timestamp: new Date(Date.now() - 3_600_000).toISOString() },
    ]) {
      expect(verifyProof(leaf.cert, { ...base, ...changed }, sig)).toBe(false);
    }
    const stranger = await setup();
    expect(verifyProof(leaf.cert, base, signProof(stranger.key, base))).toBe(
      false,
    );
    expect(verifyProof(leaf.cert, base, 'not base64 !!')).toBe(false);
  });
});
