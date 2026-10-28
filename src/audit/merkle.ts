import { createHash } from 'node:crypto';

/**
 * RFC 6962 Merkle tree over `AuditEvent.eventHash` values (hex). Used for
 * the per-second signed checkpoints (SEALs, docs/audit-chain.md): a
 * checkpoint stores one root per partition range, and an inclusion proof of
 * ~log2(n) sibling hashes shows one event belongs to that root.
 *
 * Leaf = SHA-256(0x00 ‖ leaf bytes), node = SHA-256(0x01 ‖ left ‖ right),
 * and a tree of n leaves splits at the largest power of two below n. The
 * 0x00/0x01 prefixes keep a leaf from ever being passed off as a node.
 */
export interface MerkleProofStep {
  /** Where the sibling sits relative to the path being proved. */
  side: 'L' | 'R';
  hash: string;
}

const sha256 = (...parts: Buffer[]) =>
  createHash('sha256').update(Buffer.concat(parts)).digest();

const LEAF = Buffer.from([0x00]);
const NODE = Buffer.from([0x01]);

const DIGEST = /^[0-9a-f]{64}$/;
const isDigest = (hex: unknown): hex is string =>
  typeof hex === 'string' && DIGEST.test(hex);

/**
 * `Buffer.from(hex, 'hex')` stops at the first non-hex character instead of
 * failing, so two different strings could hash the same. Only exact 64-char
 * lowercase digests are ever decoded.
 */
function digestBytes(hex: string): Buffer {
  if (!isDigest(hex)) throw new Error('not a sha256 hex digest');
  return Buffer.from(hex, 'hex');
}

const leafHash = (hex: string) => sha256(LEAF, digestBytes(hex));
const nodeHash = (left: Buffer, right: Buffer) => sha256(NODE, left, right);

/** Largest power of two strictly below n (n ≥ 2). */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function root(leaves: string[]): Buffer {
  if (leaves.length === 1) return leafHash(leaves[0]!);
  const k = split(leaves.length);
  return nodeHash(root(leaves.slice(0, k)), root(leaves.slice(k)));
}

export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) throw new Error('empty tree');
  return root(leaves).toString('hex');
}

export function inclusionProof(
  leaves: string[],
  index: number,
): MerkleProofStep[] {
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new RangeError(
      `leaf index ${index} outside tree of ${leaves.length}`,
    );
  }
  // Built top-down, returned bottom-up (the order a verifier hashes in).
  const steps: MerkleProofStep[] = [];
  let lo = 0;
  let hi = leaves.length;
  while (hi - lo > 1) {
    const k = split(hi - lo);
    const mid = lo + k;
    if (index < mid) {
      steps.push({
        side: 'R',
        hash: root(leaves.slice(mid, hi)).toString('hex'),
      });
      hi = mid;
    } else {
      steps.push({
        side: 'L',
        hash: root(leaves.slice(lo, mid)).toString('hex'),
      });
      lo = mid;
    }
  }
  return steps.reverse();
}

export function verifyInclusion(
  leaf: string,
  proof: MerkleProofStep[],
  expectedRoot: string,
): boolean {
  if (!isDigest(leaf) || !isDigest(expectedRoot)) return false;
  if (
    !proof.every((s) => (s.side === 'L' || s.side === 'R') && isDigest(s.hash))
  ) {
    return false;
  }
  let acc = leafHash(leaf);
  for (const step of proof) {
    const sibling = digestBytes(step.hash);
    acc = step.side === 'L' ? nodeHash(sibling, acc) : nodeHash(acc, sibling);
  }
  return acc.toString('hex') === expectedRoot;
}
