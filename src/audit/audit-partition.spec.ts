import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AUDIT_PARTITIONS, partitionFor } from './audit-partition';

describe('partitionFor', () => {
  it('has 64 partitions', () => {
    expect(AUDIT_PARTITIONS).toBe(64);
  });

  it("puts a human's event about an agent in that agent's partition", () => {
    const agentId = randomUUID();
    expect(partitionFor({ type: 'human', id: 'user-1' }, { agentId })).toBe(
      partitionFor({ type: 'agent', id: agentId }, null),
    );
  });

  it('falls back to the actor id when data names no agent', () => {
    expect(partitionFor({ type: 'human', id: 'user-7' }, { agentId: '' })).toBe(
      partitionFor({ type: 'human', id: 'user-7' }, null),
    );
    expect(partitionFor({ type: 'system', id: 'system:x' }, 'text')).toBe(
      partitionFor({ type: 'system', id: 'system:x' }, null),
    );
  });

  it('is stable across calls', () => {
    const actor = { type: 'system' as const, id: 'system:x' };
    expect(partitionFor(actor, null)).toBe(partitionFor(actor, null));
  });

  it('spreads 10,000 agents over all 64 partitions, none above twice the mean', () => {
    const counts = new Array<number>(64).fill(0);
    for (let i = 0; i < 10_000; i++) {
      const p = partitionFor({ type: 'agent', id: randomUUID() }, null);
      expect(Number.isInteger(p) && p >= 0 && p <= 63).toBe(true);
      counts[p]! += 1;
    }
    expect(counts.every((c) => c > 0)).toBe(true);
    expect(Math.max(...counts)).toBeLessThanOrEqual((2 * 10_000) / 64);
  });
});
