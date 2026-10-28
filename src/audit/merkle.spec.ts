import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { inclusionProof, merkleRoot, verifyInclusion } from './merkle';

const leafOf = (i: number) =>
  createHash('sha256').update(String(i)).digest('hex');
const L = [0, 1, 2, 3, 4].map(leafOf);

describe('merkleRoot', () => {
  it('matches RFC 6962 roots', () => {
    expect(merkleRoot(L.slice(0, 1))).toBe(
      '13a77175e35eb1d9da91ee14df0d7772cea71289800206e2b45c882ecb06efbf',
    );
    expect(merkleRoot(L.slice(0, 2))).toBe(
      'bbb441530bdded54e6e2bfcdc829819ff39b30768eb9f023071dffc16b410f10',
    );
    expect(merkleRoot(L.slice(0, 3))).toBe(
      '8be871f13785b4c81a1700459c76ac2b3ae2caebb7876c376e223c6adff98c47',
    );
    expect(merkleRoot(L)).toBe(
      '4e23fb40d8876f1299cca9b3c28432a01b11d1a20126606914612892ff2e09a7',
    );
  });

  it('throws on an empty tree', () => {
    expect(() => merkleRoot([])).toThrow('empty tree');
  });
});

describe('inclusionProof / verifyInclusion', () => {
  it('proves every leaf of trees of size 1..33', () => {
    for (let n = 1; n <= 33; n++) {
      const leaves = Array.from({ length: n }, (_, i) => leafOf(i));
      const root = merkleRoot(leaves);
      for (let i = 0; i < n; i++) {
        expect(
          verifyInclusion(leaves[i]!, inclusionProof(leaves, i), root),
        ).toBe(true);
      }
    }
  });

  it('keeps proofs short: ~log2(n) steps', () => {
    const leaves = Array.from({ length: 1_000_000 >> 10 }, (_, i) => leafOf(i));
    expect(inclusionProof(leaves, 500).length).toBeLessThanOrEqual(10);
  });

  it('rejects a proof for a changed leaf, a changed sibling, or the wrong root', () => {
    const leaves = L;
    const root = merkleRoot(leaves);
    const proof = inclusionProof(leaves, 2);

    expect(verifyInclusion(leafOf(99), proof, root)).toBe(false);

    const tampered = proof.map((step, i) =>
      i === 0 ? { ...step, hash: leafOf(98) } : step,
    );
    expect(verifyInclusion(leaves[2]!, tampered, root)).toBe(false);

    expect(verifyInclusion(leaves[2]!, proof, merkleRoot(L.slice(0, 3)))).toBe(
      false,
    );
  });

  it('rejects an index outside the tree', () => {
    expect(() => inclusionProof(L, 5)).toThrow();
    expect(() => inclusionProof(L, -1)).toThrow();
  });
});
