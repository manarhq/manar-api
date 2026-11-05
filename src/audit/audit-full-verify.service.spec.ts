import { describe, expect, it } from 'vitest';
import {
  AuditFullVerifyService,
  composeVerifyResponse,
  lastNightlyBoundary,
  statusOf,
} from './audit-full-verify.service';

const H = 3_600_000;
const now = Date.parse('2026-11-05T12:00:00Z');
const row = (over: Partial<NonNullable<Parameters<typeof statusOf>[0]>>) => ({
  verifiedAt: new Date(now - 2 * H),
  result: 'passed',
  brokenAt: null,
  lastPassedAt: new Date(now - 2 * H),
  durationMs: 10,
  ...over,
});

describe('statusOf', () => {
  it('never / passed / stale / failed / error', () => {
    expect(statusOf(null, now).state).toBe('never');
    expect(statusOf(row({ result: null }), now).state).toBe('never');
    expect(statusOf(row({}), now).state).toBe('passed');
    const old = new Date(now - AuditFullVerifyService.STALE_MS - H);
    expect(
      statusOf(row({ lastPassedAt: old, verifiedAt: old }), now).state,
    ).toBe('stale');
    expect(
      statusOf(row({ result: 'failed', brokenAt: 'e1' }), now),
    ).toMatchObject({
      state: 'failed',
      brokenAt: 'e1',
    });
  });

  it('a run that errored after a pass is "error", not the old "passed" (the pass time is kept for display)', () => {
    const passedAt = new Date(now - 30 * H);
    const s = statusOf(
      row({
        result: 'error',
        verifiedAt: new Date(now - H),
        lastPassedAt: passedAt,
      }),
      now,
    );
    expect(s.state).toBe('error');
    expect(s.lastFullVerifiedAt).toEqual(passedAt);
  });
});

describe('composeVerifyResponse', () => {
  const at = new Date('2026-11-05T10:00:00Z');
  const passed = {
    state: 'passed' as const,
    lastFullVerifiedAt: at,
    brokenAt: null,
  };
  const none = (state: 'never' | 'stale' | 'error') => ({
    state,
    lastFullVerifiedAt: state === 'never' ? null : at,
    brokenAt: null,
  });
  const resumed = { valid: true as const, coveredFrom: { sealSeq: '7', at } };

  it('valid only when the incremental passed and a fresh full check passed', () => {
    expect(composeVerifyResponse(resumed, passed)).toMatchObject({
      valid: true,
      status: 'verified',
      fullCheck: 'passed',
    });
  });

  it.each(['never', 'stale', 'error'] as const)(
    'incremental-only coverage with full check %s is partial, never valid, and says from where',
    (state) => {
      const r = composeVerifyResponse(resumed, none(state));
      expect(r).toMatchObject({
        valid: false,
        status: 'partial',
        fullCheck: state,
        coveredFrom: { sealSeq: '7', at: at.toISOString() },
      });
      expect(r.brokenAt).toBeUndefined();
    },
  );

  it('an incremental run that walked the whole log is verified without a nightly result', () => {
    expect(composeVerifyResponse({ valid: true }, none('never'))).toMatchObject(
      {
        valid: true,
        status: 'verified',
      },
    );
  });

  it('a failed last full check or a failed incremental is broken', () => {
    expect(
      composeVerifyResponse(resumed, {
        state: 'failed',
        lastFullVerifiedAt: null,
        brokenAt: 'e9',
      }),
    ).toMatchObject({ valid: false, status: 'broken', brokenAt: 'e9' });
    expect(
      composeVerifyResponse({ valid: false, brokenAt: 'c:1' }, passed),
    ).toMatchObject({ valid: false, status: 'broken', brokenAt: 'c:1' });
  });
});

describe('lastNightlyBoundary', () => {
  it('is the most recent 22:00 UTC', () => {
    expect(
      lastNightlyBoundary(new Date('2026-11-05T10:00:00Z')).toISOString(),
    ).toBe('2026-11-04T22:00:00.000Z');
    expect(
      lastNightlyBoundary(new Date('2026-11-05T22:30:00Z')).toISOString(),
    ).toBe('2026-11-05T22:00:00.000Z');
  });
});
