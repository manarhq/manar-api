import { describe, expect, it } from 'vitest';
import {
  renderCompanyTrialReminder,
  renderTrialReminder,
  renderUsageAlert,
} from './billing-mail';
import { dayOf, meterTarget } from './meter-targets';
import { highestPerKind } from './usage-alerts.service';
import { thresholdKeys } from './wallet.service';

describe('meterTarget', () => {
  it('Pro bills active devices beyond the 2 included', () => {
    expect(meterTarget('pro', 0, null)).toEqual({
      meter: 'manar_pro_extra_devices',
      target: 0,
    });
    expect(meterTarget('pro', 2, null)?.target).toBe(0);
    expect(meterTarget('pro', 5, null)?.target).toBe(3);
  });

  it('Company monthly bills at least 3 seats, then every active seat', () => {
    expect(meterTarget('company', 0, null)).toEqual({
      meter: 'manar_company_seats',
      target: 3,
    });
    expect(meterTarget('company', 5, null)?.target).toBe(5);
  });

  it('Company yearly bills only seats above the commitment (itself at least 3)', () => {
    expect(meterTarget('company', 8, 10)?.target).toBe(0);
    expect(meterTarget('company', 12, 10)?.target).toBe(2);
    expect(meterTarget('company', 4, 1)?.target).toBe(1);
  });

  it('trials and Free bill nothing', () => {
    for (const p of ['free', 'trial', 'company_trial', 'enterprise'] as const)
      expect(meterTarget(p, 50, null)).toBeNull();
  });

  it('dayOf is the UTC calendar day', () => {
    expect(dayOf(new Date('2026-11-04T23:59:59.000Z')).toISOString()).toBe(
      '2026-11-04T00:00:00.000Z',
    );
  });
});

describe('alert thresholds', () => {
  const base = {
    aiUsed: 0,
    minutesUsed: 0,
    creditsSpent: 0,
    aiIncluded: 300,
    minutesIncluded: 300,
    cap: 4000,
    balance: 5000,
    autoTopUp: false,
    wallet: true,
  };
  it('50, 80 and 100% of the allowance and of the cap', () => {
    expect(thresholdKeys({ ...base, aiUsed: 150 })).toEqual(['ai:50']);
    expect(thresholdKeys({ ...base, aiUsed: 300, minutesUsed: 240 })).toEqual([
      'ai:50',
      'ai:80',
      'ai:100',
      'minutes:50',
      'minutes:80',
    ]);
    expect(thresholdKeys({ ...base, creditsSpent: 4000 })).toEqual([
      'cap:50',
      'cap:80',
      'cap:100',
    ]);
  });

  it('low credits only once credits matter and auto top-up is off', () => {
    expect(thresholdKeys({ ...base, balance: 0 })).toEqual([]);
    expect(thresholdKeys({ ...base, balance: 100, aiUsed: 250 })).toContain(
      'credits:low',
    );
    expect(thresholdKeys({ ...base, balance: 0, creditsSpent: 9 })).toContain(
      'credits:low',
    );
    // Never bought any: the allowance alerts say it, not "low credits".
    expect(thresholdKeys({ ...base, balance: 0, aiUsed: 250 })).not.toContain(
      'credits:low',
    );
    expect(
      thresholdKeys({ ...base, balance: 100, aiUsed: 250, autoTopUp: true }),
    ).not.toContain('credits:low');
    // No cap (Free): no cap alerts.
    expect(
      thresholdKeys({
        ...base,
        cap: null,
        aiIncluded: 20,
        aiUsed: 20,
        balance: 5000,
      }),
    ).toEqual(['ai:50', 'ai:80', 'ai:100']);
  });

  it('one email per kind: the highest new step', () => {
    expect(highestPerKind(['ai:50', 'ai:80', 'cap:50', 'credits:low'])).toEqual(
      ['ai:80', 'cap:50', 'credits:low'],
    );
  });
});

describe('billing emails', () => {
  it('every usage alert says protection keeps working, in EN and AR', () => {
    for (const key of ['ai:100', 'minutes:80', 'cap:100', 'credits:low']) {
      const en = renderUsageAlert({ locale: 'en', key, link: 'https://c/x' });
      expect(en.text).toContain('Protection is not affected');
      const ar = renderUsageAlert({ locale: 'ar', key, link: 'https://c/x' });
      expect(ar.html).toContain('dir="rtl"');
      expect(ar.text).toContain('الحماية لا تتأثر');
    }
  });

  it('the trial reminder shows what Manar blocked and escapes the link', () => {
    const m = renderTrialReminder({
      locale: 'en',
      daysLeft: 4,
      blocked: 12,
      link: 'https://c/"><script>',
    });
    expect(m.subject).toBe('Your Manar trial ends in 4 days');
    expect(m.text).toContain('Manar blocked 12 risky actions');
    expect(m.html).not.toContain('<script>');
    expect(
      renderTrialReminder({ locale: 'ar', daysLeft: 0, blocked: 0, link: 'x' })
        .subject,
    ).toBe('تنتهي تجربتك في منار اليوم');
  });

  it('no banned words in any billing email', () => {
    const banned =
      /\b(immutable|unhackable|tamper[- ]?proof|100% safe|provably safe|physically impossible|guaranteed)\b/i;
    for (const locale of ['en', 'ar'] as const) {
      for (const key of ['ai:50', 'ai:100', 'cap:80', 'credits:low'])
        expect(renderUsageAlert({ locale, key, link: 'x' }).text).not.toMatch(
          banned,
        );
      expect(
        renderTrialReminder({ locale, daysLeft: 1, blocked: 1, link: 'x' })
          .text,
      ).not.toMatch(banned);
      expect(
        renderCompanyTrialReminder({ locale, daysLeft: 2, link: 'x' }).text,
      ).not.toMatch(banned);
    }
  });
});
