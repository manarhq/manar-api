import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { canonicalize } from './canonical-json';
import { computeEventHash } from './audit-hash';

describe('computeEventHash', () => {
  const content = {
    id: 'evt-1',
    eventType: 'task.created',
    correlationId: 'corr-1',
    actor: { type: 'human' as const, id: 'user-1' },
    timestamp: '2026-08-19T00:00:00.000Z',
    data: { taskId: 'task-1' },
    previousHash: null,
  };

  it('equals sha256(canonicalize(content)) — the exact formula from the design spec', () => {
    const expected = createHash('sha256')
      .update(canonicalize(content), 'utf8')
      .digest('hex');
    expect(computeEventHash(content)).toBe(expected);
  });

  it('is a 64-character lowercase hex string', () => {
    expect(computeEventHash(content)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic regardless of key insertion order in the caller-constructed object', () => {
    const reordered = {
      previousHash: content.previousHash,
      data: content.data,
      timestamp: content.timestamp,
      actor: content.actor,
      correlationId: content.correlationId,
      eventType: content.eventType,
      id: content.id,
    };
    expect(computeEventHash(reordered)).toBe(computeEventHash(content));
  });

  it('changes when previousHash changes — links events into a chain', () => {
    const withPrevious = computeEventHash({
      ...content,
      previousHash: 'some-prior-hash',
    });
    expect(withPrevious).not.toBe(computeEventHash(content));
  });

  it('changes when data changes even with everything else identical', () => {
    const changed = computeEventHash({
      ...content,
      data: { taskId: 'task-2' },
    });
    expect(changed).not.toBe(computeEventHash(content));
  });
});
