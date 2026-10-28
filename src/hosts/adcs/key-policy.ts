import { createPublicKey } from 'node:crypto';
import type * as x509 from '@peculiar/x509';

const SIG_NAMES = new Set(['RSASSA-PKCS1-v1_5', 'RSA-PSS', 'ECDSA']);
const SIG_HASHES = new Set(['SHA-256', 'SHA-384', 'SHA-512']);

/** RSA of at least 2048 bits, or EC on P-256 / P-384. Nothing else. */
export function keyAcceptable(spkiDer: Uint8Array): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.from(spkiDer),
      format: 'der',
      type: 'spki',
    });
    const d = key.asymmetricKeyDetails;
    if (key.asymmetricKeyType === 'rsa') return (d?.modulusLength ?? 0) >= 2048;
    if (key.asymmetricKeyType === 'ec') {
      return d?.namedCurve === 'prime256v1' || d?.namedCurve === 'secp384r1';
    }
    return false;
  } catch {
    return false;
  }
}

/** RSA PKCS#1 v1.5 / PSS or ECDSA, with SHA-256, SHA-384 or SHA-512 only. */
export function signatureAcceptable(cert: x509.X509Certificate): boolean {
  const alg = cert.signatureAlgorithm as {
    name?: string;
    hash?: { name?: string };
  };
  return SIG_NAMES.has(alg.name ?? '') && SIG_HASHES.has(alg.hash?.name ?? '');
}
