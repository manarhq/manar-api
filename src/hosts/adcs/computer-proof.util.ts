import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import type * as x509 from '@peculiar/x509';

/** How far a proof's timestamp may differ from the server clock. */
export const PROOF_SKEW_MS = 5 * 60_000;

/** SHA-256 of a CSR's SubjectPublicKeyInfo, as hex (the host's key fingerprint). */
export function spkiFingerprint(spkiDer: Uint8Array): string {
  return createHash('sha256').update(spkiDer).digest('hex');
}

/**
 * What the computer certificate's key signs. It names the tenant, the
 * machine and the CSR key the new host certificate will be issued for, so
 * a captured proof cannot be reused for another key, machine or tenant.
 */
export function proofMessage(input: {
  tenantSlug: string;
  machineId: string;
  csrKeyFingerprint: string;
  timestamp: string;
}): Buffer {
  return Buffer.from(
    [
      'manar-adcs-register-v1',
      input.tenantSlug,
      input.machineId,
      input.csrKeyFingerprint,
      input.timestamp,
    ].join('\n'),
    'utf8',
  );
}

export function signProof(
  privateKey: KeyObject,
  input: Parameters<typeof proofMessage>[0],
): string {
  return sign('sha256', proofMessage(input), privateKey).toString('base64');
}

/**
 * True when `signature` was made by the key of `cert` over the proof
 * message and the timestamp is fresh. RSA (PKCS#1 v1.5) and ECDSA (DER),
 * both with SHA-256.
 */
export function verifyProof(
  cert: x509.X509Certificate,
  input: Parameters<typeof proofMessage>[0],
  signature: string,
  now: Date = new Date(),
): boolean {
  const at = Date.parse(input.timestamp);
  if (!Number.isFinite(at) || Math.abs(now.getTime() - at) > PROOF_SKEW_MS) {
    return false;
  }
  try {
    const key = createPublicKey({
      key: Buffer.from(cert.publicKey.rawData),
      format: 'der',
      type: 'spki',
    });
    return verify(
      'sha256',
      proofMessage(input),
      key,
      Buffer.from(signature, 'base64'),
    );
  } catch {
    return false;
  }
}
