import { describe, expect, it } from 'vitest';
import { dueNow, localParts, renderDigest, validZone } from './digest';

describe('weekly digest timing', () => {
  // Monday 2 Nov 2026 04:00 UTC = 08:00 in Dubai (UTC+4)
  const mon0800Dubai = new Date('2026-11-02T04:00:00Z');
  it('is due Monday 08:00 in the user zone, default Asia/Dubai', () => {
    expect(dueNow(mon0800Dubai, null).due).toBe(true);
    expect(dueNow(mon0800Dubai, 'Asia/Dubai').due).toBe(true);
    expect(dueNow(mon0800Dubai, 'Europe/London').due).toBe(false); // 04:00 local
    expect(dueNow(new Date('2026-11-02T08:00:00Z'), 'Europe/London').due).toBe(
      true,
    );
  });
  it('is not due Sunday night, or after the window', () => {
    expect(dueNow(new Date('2026-11-01T04:00:00Z'), null).due).toBe(false);
    expect(dueNow(new Date('2026-11-02T08:30:00Z'), null).due).toBe(false); // 12:30 Dubai
  });
  it('uses the local date for the week label', () => {
    // Sunday 22:00 UTC is already Monday 02:00 in Dubai
    expect(
      localParts(new Date('2026-11-01T22:00:00Z'), 'Asia/Dubai'),
    ).toMatchObject({ weekday: 1, week: '2026-W45' });
    expect(localParts(new Date('2026-11-01T22:00:00Z'), 'UTC').week).toBe(
      '2026-W44',
    );
  });
  it('falls back to the default zone for junk', () => {
    expect(validZone('Not/AZone')).toBe('Asia/Dubai');
  });
});

describe('weekly digest email', () => {
  const t = { actions: 1200, askedYou: 4, blocked: 2, secretsKeptSafe: 1 };
  it('renders English and right-to-left Arabic with the unsubscribe link', () => {
    const en = renderDigest({
      locale: 'en',
      totals: t,
      consoleUrl: 'https://c/',
      unsubscribeUrl: 'https://u/x',
    });
    expect(en.html).toContain('dir="ltr"');
    expect(en.html).toContain('https://u/x');
    expect(en.text).toContain('1,200');
    const ar = renderDigest({
      locale: 'ar',
      totals: t,
      consoleUrl: 'https://c/',
      unsubscribeUrl: 'https://u/x',
    });
    expect(ar.html).toContain('dir="rtl"');
    expect(ar.subject).toContain('منار');
  });
});
