import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalize } from '../canonical-json';

/**
 * The pure parts of a SEAL (signed audit checkpoint): its content, the hash
 * that is signed, and signature checks. Kept free of OpenBao and any network
 * client so `AuditService`, which sits on the synchronous decision path
 * (`decision-path-dependencies.spec.ts`), can verify SEALs without importing
 * one.
 */
export interface PartitionHead {
  partition: number;
  seq: string;
  eventHash: string;
}

export interface PartitionRoot {
  partition: number;
  fromSeq: string;
  toSeq: string;
  root: string;
}

export interface CheckpointPublicKey {
  keyId: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
}

/** Looks up a tenant's SEAL public key (provided by `CheckpointSigner`). */
export interface CheckpointKeyLookup {
  /** Creates the key on first use. */
  publicKey(tenantId: string): Promise<CheckpointPublicKey>;
  /**
   * Whether the tenant's key exists yet (it is created by the first SEAL).
   * Kept in OpenBao, outside the audit tables, so deleting every SEAL can't
   * also erase the evidence that SEALs were being written.
   */
  hasKey(tenantId: string): Promise<boolean>;
}

export const CHECKPOINT_PUBLIC_KEYS = Symbol('CHECKPOINT_PUBLIC_KEYS');

const DIGEST = /^[0-9a-f]{64}$/;

/** The exact content a checkpoint's hash and signature cover. */
export function checkpointHashOf(content: {
  seq: bigint;
  createdAt: Date;
  partitionHeads: PartitionHead[];
  roots: PartitionRoot[];
  previousCheckpointHash: string | null;
}): string {
  return createHash('sha256')
    .update(
      canonicalize({
        // Domain label: a SEAL digest can never be mistaken for an anchor's.
        domain: 'manar.audit.seal.v1',
        seq: content.seq.toString(),
        createdAt: content.createdAt.toISOString(),
        partitionHeads: content.partitionHeads,
        roots: content.roots,
        previousCheckpointHash: content.previousCheckpointHash,
      }),
      'utf8',
    )
    .digest('hex');
}

export function verifyCheckpointSignature(
  checkpointHashHex: string,
  signatureB64: string,
  publicKeyPem: string,
): boolean {
  if (!DIGEST.test(checkpointHashHex)) return false;
  try {
    return verify(
      null,
      Buffer.from(checkpointHashHex, 'hex'),
      createPublicKey(publicKeyPem),
      Buffer.from(signatureB64, 'base64'),
    );
  } catch {
    return false;
  }
}

/**
 * What retention signs for each anchor, so a planted anchor can't excuse
 * deleted events (only the retention process holds the tenant key).
 */
export function anchorDigestOf(anchor: {
  tenantId: string;
  partition: number;
  anchorHash: string;
  eventsPrunedCount: number;
}): string {
  return createHash('sha256')
    .update(
      canonicalize({
        domain: 'manar.audit.anchor.v1',
        tenantId: anchor.tenantId,
        partition: anchor.partition,
        anchorHash: anchor.anchorHash,
        eventsPrunedCount: anchor.eventsPrunedCount,
      }),
      'utf8',
    )
    .digest('hex');
}

/** First 16 hex chars of SHA-256 over the key's SPKI DER. */
export function keyIdOf(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({
    type: 'spki',
    format: 'der',
  });
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}
