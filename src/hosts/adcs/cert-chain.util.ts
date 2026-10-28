import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { keyAcceptable, signatureAcceptable } from './key-policy';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

export type ChainFailure =
  | 'unparseable'
  | 'untrusted'
  | 'expired'
  | 'not_yet_valid'
  | 'wrong_eku'
  | 'not_a_ca'
  | 'too_deep'
  | 'path_length'
  | 'critical_extension'
  | 'ca_eku'
  | 'weak_algorithm';

/** A certificate was not acceptable; `reason` is for the log, never for the caller. */
export class CertChainError extends Error {
  constructor(readonly reason: ChainFailure) {
    super(`certificate chain refused: ${reason}`);
  }
}

const MAX_DEPTH = 5;
export const EKU_CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';
const EKU_ANY = '2.5.29.37.0';

/** Extensions this validator evaluates. Any other critical extension means refuse (RFC 5280 4.2). */
const PROCESSED_CRITICAL = new Set([
  '2.5.29.19', // basicConstraints
  '2.5.29.15', // keyUsage
  '2.5.29.37', // extendedKeyUsage
  '2.5.29.17', // subjectAltName (read by the caller)
  '2.5.29.14', // subjectKeyIdentifier
  '2.5.29.35', // authorityKeyIdentifier
  '2.5.29.31', // cRLDistributionPoints
]);

/**
 * Whole-path rules that need the finished chain (leaf first, anchor last):
 * no critical extension we do not evaluate (name constraints, policy
 * constraints and the like are refused, not ignored), pathLenConstraint of
 * every CA counted against the CAs below it, and an intermediate that
 * restricts EKU must allow `requireEku` (or anyExtendedKeyUsage).
 */
function checkPath(chain: x509.X509Certificate[], requireEku?: string): void {
  chain.forEach((cert, i) => {
    // The trust anchor is self-issued: its key counts, its own signature is not relied on.
    if (
      !keyAcceptable(new Uint8Array(cert.publicKey.rawData)) ||
      (i < chain.length - 1 && !signatureAcceptable(cert))
    ) {
      throw new CertChainError('weak_algorithm');
    }
  });
  for (const cert of chain) {
    if (
      cert.extensions.some((e) => e.critical && !PROCESSED_CRITICAL.has(e.type))
    ) {
      throw new CertChainError('critical_extension');
    }
  }
  for (let i = 1; i < chain.length; i += 1) {
    const max = chain[i]!.getExtension(
      x509.BasicConstraintsExtension,
    )?.pathLength;
    // CA certificates strictly between this issuer and the leaf.
    if (max !== undefined && max < i - 1)
      throw new CertChainError('path_length');
    const isAnchor = i === chain.length - 1;
    const eku = chain[i]!.getExtension(x509.ExtendedKeyUsageExtension);
    if (requireEku && !isAnchor && eku) {
      const usages = eku.usages.map(String);
      if (!usages.includes(requireEku) && !usages.includes(EKU_ANY)) {
        throw new CertChainError('ca_eku');
      }
    }
  }
}

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
      if (anchors.some((a) => same(a, issuer))) {
        checkPath(chain, input.requireEku);
        return { leaf, chain };
      }
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
