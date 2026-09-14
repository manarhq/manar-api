import { createHash, timingSafeEqual } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { constantTimeEqual } from './constant-time-compare';

/**
 * `constantTimeEqual`'s security property (no early return, no
 * length-dependent branch) cannot be asserted by measuring wall-clock time
 * in a unit test — a JIT-warmed microbenchmark on a shared CI runner is
 * far too noisy to distinguish a real timing leak from scheduler jitter,
 * and a test that tried would be flaky rather than meaningful. What these
 * tests pin instead is the behaviour that property depends on: the
 * function returns a correct answer — never throws, never short-circuits
 * into a different code path — for inputs of *differing* length, which is
 * the case a naive `timingSafeEqual` call site has to special-case with an
 * early return (`timingSafeEqual` throws on differing-length buffers).
 * The constant-time property itself is a review-level guarantee of the
 * implementation: fixed-width digests, no length comparison, no early
 * return.
 */
describe('constantTimeEqual', () => {
  it('accepts two identical secrets', () => {
    expect(constantTimeEqual('s3cret-token-value', 's3cret-token-value')).toBe(
      true,
    );
  });

  it('rejects two different secrets of the same length', () => {
    expect(constantTimeEqual('s3cret-token-value', 's3cret-token-valuf')).toBe(
      false,
    );
  });

  it('rejects a secret that is a prefix of the expected one', () => {
    expect(constantTimeEqual('s3cret', 's3cret-token-value')).toBe(false);
  });

  it('rejects a secret that is longer than the expected one', () => {
    expect(constantTimeEqual('s3cret-token-value-and-more', 's3cret')).toBe(
      false,
    );
  });

  it('rejects an empty provided secret', () => {
    expect(constantTimeEqual('', 's3cret-token-value')).toBe(false);
  });

  it('compares multi-byte UTF-8 secrets by their bytes, not their code units', () => {
    expect(constantTimeEqual('مِفتاح-سِرّي', 'مِفتاح-سِرّي')).toBe(true);
    expect(constantTimeEqual('مِفتاح-سِرّي', 'مِفتاح-سِرّى')).toBe(false);
  });

  it('agrees with a hand-computed SHA-256 digest comparison', () => {
    const digest = (value: string) =>
      createHash('sha256').update(value, 'utf8').digest();
    expect(constantTimeEqual('alpha', 'alpha')).toBe(
      timingSafeEqual(digest('alpha'), digest('alpha')),
    );
  });
});
