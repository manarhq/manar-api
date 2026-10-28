import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export type ChainFailure =
  | 'unparseable'
  | 'untrusted'
  | 'expired'
  | 'not_yet_valid'
  | 'wrong_eku'
  | 'not_a_ca'
  | 'too_deep';

/** A certificate was not acceptable; `reason` is for the log, never for the caller. */
export class CertChainError extends Error {
  constructor(readonly reason: ChainFailure) {
    super(`certificate chain refused: ${reason}`);
  }
}

const MAX_DEPTH = 5;
export const EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

export function parsePem(pem: string): x509.X509Certificate {
  try {
    return new x509.X509Certificate(pem);
  } catch {
    throw new CertChainError('unparseable');
  }
}

const same = (a: x509.X509Certificate, b: x509.X509Certificate) =>
  Buffer.compare(Buffer.from(a.rawData), Buffer.from(b.rawData)) === 0;

function assertValidAt(cert: x509.X509Certificate, now: Date): void {
  if (now < cert.notBefore) throw new CertChainError('not_yet_valid');
  if (now > cert.notAfter) throw new CertChainError('expired');
}

function isCa(cert: x509.X509Certificate): boolean {
  const bc = cert.getExtension(x509.BasicConstraintsExtension);
  if (!bc?.ca) return false;
  const ku = cert.getExtension(x509.KeyUsagesExtension);
  return !ku || (ku.usages & x509.KeyUsageFlags.keyCertSign) !== 0;
}

export interface ValidatedChain {
  leaf: x509.X509Certificate;
  /** Leaf first, trust anchor last. */
  chain: x509.X509Certificate[];
}

/**
 * Builds leaf -> (presented intermediates) -> one of `anchorsPem` and checks
 * every signature, the validity window of every certificate at `now`, that
 * each issuer is a CA, and (when `requireEku` is set) that the leaf carries
 * that extended key usage. A leaf with no EKU extension is refused when an
 * EKU is required. Throws `CertChainError`.
 */
export async function validateChain(input: {
  leafPem: string;
  intermediatesPem?: string[];
  anchorsPem: string[];
  now?: Date;
  requireEku?: string;
}): Promise<ValidatedChain> {
  const now = input.now ?? new Date();
  const leaf = parsePem(input.leafPem);
  const intermediates = (input.intermediatesPem ?? []).map(parsePem);
  const anchors = input.anchorsPem.map(parsePem);
  if (anchors.length === 0) throw new CertChainError('untrusted');

  assertValidAt(leaf, now);
  if (input.requireEku) {
    const eku = leaf.getExtension(x509.ExtendedKeyUsageExtension);
    if (!eku || !eku.usages.map(String).includes(input.requireEku)) {
      throw new CertChainError('wrong_eku');
    }
  }

  const chain = [leaf];
  let current = leaf;
  let sawExpiry: ChainFailure | null = null;
  for (let depth = 0; depth < MAX_DEPTH; depth += 1) {
    let advanced = false;
    // A leaf that is itself a stored anchor is not accepted: anchors are CAs.
    const candidates = [...anchors, ...intermediates].filter(
      (c) => c.subject === current.issuer && !same(c, current),
    );
    for (const issuer of candidates) {
      let signed = false;
      try {
        signed = await current.verify({
          publicKey: issuer.publicKey,
          signatureOnly: true,
        });
      } catch {
        signed = false;
      }
      if (!signed) continue;
      if (!isCa(issuer)) throw new CertChainError('not_a_ca');
      try {
        assertValidAt(issuer, now);
      } catch (error) {
        sawExpiry = (error as CertChainError).reason;
        continue;
      }
      chain.push(issuer);
      if (anchors.some((a) => same(a, issuer))) return { leaf, chain };
      current = issuer;
      advanced = true;
      break;
    }
    if (!advanced) {
      throw new CertChainError(sawExpiry ?? 'untrusted');
    }
  }
  throw new CertChainError('too_deep');
}
