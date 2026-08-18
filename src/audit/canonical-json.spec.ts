import { describe, expect, it } from 'vitest';
import { canonicalize } from './canonical-json';

describe('canonicalize', () => {
  it('produces identical output for objects with differently ordered keys', () => {
    const a = { b: 1, a: 2, c: 3 };
    const b = { c: 3, a: 2, b: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it('sorts keys recursively, at every depth', () => {
    const a = { outer: { z: 1, y: { b: 2, a: 1 } }, first: 'x' };
    const b = { first: 'x', outer: { y: { a: 1, b: 2 }, z: 1 } };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it('never reorders array elements — array order is semantically significant', () => {
    const withOrder1 = { rules: [{ id: 1 }, { id: 2 }] };
    const withOrder2 = { rules: [{ id: 2 }, { id: 1 }] };
    expect(canonicalize(withOrder1)).not.toBe(canonicalize(withOrder2));
  });

  it('sorts keys inside objects nested within arrays', () => {
    const a = { list: [{ b: 1, a: 2 }] };
    const b = { list: [{ a: 2, b: 1 }] };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it('normalizes Date instances to their ISO-8601 string form', () => {
    const date = new Date('2026-08-19T12:34:56.000Z');
    expect(canonicalize({ when: date })).toBe(
      JSON.stringify({ when: '2026-08-19T12:34:56.000Z' }),
    );
  });

  it('treats null and undefined as null', () => {
    expect(canonicalize(null)).toBe('null');
    expect(canonicalize(undefined)).toBe('null');
  });

  it('omits object keys whose value is undefined, matching JSON.stringify', () => {
    const withUndefined = { a: 1, b: undefined };
    expect(canonicalize(withUndefined)).toBe(JSON.stringify({ a: 1 }));
  });

  it('is deterministic across repeated calls with the same input', () => {
    const value = { z: [3, { y: 'x', a: 'b' }], a: 1 };
    const first = canonicalize(value);
    const second = canonicalize(value);
    expect(first).toBe(second);
  });

  it('produces different output for structurally different objects', () => {
    expect(canonicalize({ a: 1 })).not.toBe(canonicalize({ a: 2 }));
    expect(canonicalize({ a: 1, b: 2 })).not.toBe(canonicalize({ a: 1 }));
  });

  it('handles primitives directly', () => {
    expect(canonicalize('hello')).toBe('"hello"');
    expect(canonicalize(42)).toBe('42');
    expect(canonicalize(true)).toBe('true');
  });

  it('handles a realistic audit event content shape identically regardless of construction order', () => {
    const buildOne = () => ({
      id: 'evt-1',
      eventType: 'authorization.denied',
      correlationId: 'corr-1',
      actor: { type: 'agent', id: 'agent-1' },
      timestamp: '2026-08-19T00:00:00.000Z',
      data: { reason: 'not_authorized', riskScore: 42 },
      previousHash: null,
    });
    const buildTwo = () => ({
      previousHash: null,
      data: { riskScore: 42, reason: 'not_authorized' },
      timestamp: '2026-08-19T00:00:00.000Z',
      actor: { id: 'agent-1', type: 'agent' },
      correlationId: 'corr-1',
      eventType: 'authorization.denied',
      id: 'evt-1',
    });
    expect(canonicalize(buildOne())).toBe(canonicalize(buildTwo()));
  });
});
