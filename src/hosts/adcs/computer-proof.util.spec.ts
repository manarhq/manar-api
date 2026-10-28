import 'reflect-metadata';
import { createPrivateKey } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { webcrypto } from 'node:crypto';
import {
  makeCa,
  makeLeaf,
  newEcKeys,
  newRsaKeys,
} from '../../../test/support/test-pki';
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

  it('refuses a proof from a weak key even when the signature is valid', async () => {
    const ca = await makeCa('Proof Weak CA');
    for (const keys of [await newRsaKeys(1024), await newEcKeys('P-521')]) {
      const leaf = await makeLeaf(ca, { keys });
      const pkcs8 = Buffer.from(
        await webcrypto.subtle.exportKey('pkcs8', keys.privateKey),
      );
      const key = createPrivateKey({
        key: pkcs8,
        format: 'der',
        type: 'pkcs8',
      });
      expect(verifyProof(leaf.cert, base, signProof(key, base))).toBe(false);
    }
    const ok = await makeLeaf(ca, { keys: await newEcKeys('P-256') });
    const okKey = createPrivateKey({
      key: Buffer.from(
        await webcrypto.subtle.exportKey(
          'pkcs8',
          (await newEcKeys('P-256')).privateKey,
        ),
      ),
      format: 'der',
      type: 'pkcs8',
    });
    // a different P-256 key: valid algorithm, wrong key
    expect(verifyProof(ok.cert, base, signProof(okKey, base))).toBe(false);
  });
});
