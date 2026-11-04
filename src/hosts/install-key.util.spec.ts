import { afterEach, describe, expect, it } from 'vitest';
import {
  InstallKeyLimitError,
  installKeyLimits,
  generateInstallKey,
  hashInstallKey,
  ipAllowed,
  isValidCidr,
  legacyHashInstallKey,
  tenantSlugOf,
} from './install-key.util';

describe('install keys', () => {
  it('carries the tenant slug and 256 bits of randomness', () => {
    const raw = generateInstallKey('acme-gov');
    expect(raw).toMatch(/^mik_acme-gov_[A-Za-z0-9_-]{43}$/);
    expect(tenantSlugOf(raw)).toBe('acme-gov');
    expect(generateInstallKey('acme-gov')).not.toBe(raw);
  });

  it('rejects anything that is not an install key', () => {
    expect(tenantSlugOf('acme:agent:token')).toBeNull();
    expect(tenantSlugOf('mik__abc')).toBeNull();
    expect(tenantSlugOf('mik_acme_short')).toBeNull();
  });

  it('hashes stably to 64 hex chars', () => {
    const raw = generateInstallKey('t');
    expect(hashInstallKey(raw)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashInstallKey(raw)).toBe(hashInstallKey(raw));
  });
});

describe('ipAllowed', () => {
  it('allows any address when no ranges are set', () => {
    expect(ipAllowed('203.0.113.9', [])).toBe(true);
  });

  it('checks IPv4 and IPv6 ranges', () => {
    expect(ipAllowed('10.1.2.3', ['10.0.0.0/8'])).toBe(true);
    expect(ipAllowed('11.1.2.3', ['10.0.0.0/8'])).toBe(false);
    expect(ipAllowed('2001:db8::5', ['2001:db8::/32'])).toBe(true);
    expect(ipAllowed('2001:db9::5', ['2001:db8::/32'])).toBe(false);
  });

  it('treats an IPv4-mapped IPv6 address as its IPv4 address', () => {
    expect(ipAllowed('::ffff:10.1.2.3', ['10.0.0.0/8'])).toBe(true);
    expect(ipAllowed('::ffff:11.1.2.3', ['10.0.0.0/8'])).toBe(false);
  });

  it('rejects malformed input instead of allowing it', () => {
    expect(ipAllowed('not-an-ip', ['10.0.0.0/8'])).toBe(false);
    expect(ipAllowed('10.1.2.3', ['garbage'])).toBe(false);
  });

  it('never reads a sloppy prefix as /0 (allow-all)', () => {
    for (const sloppy of [
      '10.0.0.0/',
      '10.0.0.0/ ',
      '10.0.0.0/0x8',
      '10.0.0.0/8/8',
      '10.0.0.0',
    ]) {
      expect(ipAllowed('11.1.2.3', [sloppy])).toBe(false);
      expect(isValidCidr(sloppy)).toBe(false);
    }
    expect(isValidCidr('10.0.0.0/8')).toBe(true);
    expect(isValidCidr('2001:db8::/32')).toBe(true);
    expect(isValidCidr('10.0.0.0/33')).toBe(false);
  });
});

describe('stored hash of a key or short code', () => {
  const OLD = process.env.MANAR_INSTALL_KEY_HMAC_SECRET;
  afterEach(() => {
    if (OLD === undefined) delete process.env.MANAR_INSTALL_KEY_HMAC_SECRET;
    else process.env.MANAR_INSTALL_KEY_HMAC_SECRET = OLD;
  });

  it('is plain SHA-256 without the secret, and an HMAC under it', () => {
    delete process.env.MANAR_INSTALL_KEY_HMAC_SECRET;
    const plain = hashInstallKey('ABCDEFGH23');
    expect(plain).toBe(legacyHashInstallKey('ABCDEFGH23'));
    process.env.MANAR_INSTALL_KEY_HMAC_SECRET = 'x'.repeat(32);
    const a = hashInstallKey('ABCDEFGH23');
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(plain);
    process.env.MANAR_INSTALL_KEY_HMAC_SECRET = 'y'.repeat(32);
    expect(hashInstallKey('ABCDEFGH23')).not.toBe(a);
    // The old format stays computable, so keys made before the secret still resolve.
    expect(legacyHashInstallKey('ABCDEFGH23')).toBe(plain);
  });
});

describe('installKeyLimits (founder decision, 4 Nov 2026)', () => {
  const now = new Date('2026-11-04T00:00:00Z');
  const h = 3_600_000;
  it('defaults to 24 hours and one use', () => {
    expect(installKeyLimits({}, now)).toEqual({
      expiresAt: new Date(now.getTime() + 24 * h),
      maxUses: 1,
    });
  });
  it("takes 1 hour to 30 days, and the admin's own number of uses", () => {
    const at = new Date(now.getTime() + 30 * 24 * h);
    expect(installKeyLimits({ expiresAt: at, maxUses: 50 }, now)).toEqual({
      expiresAt: at,
      maxUses: 50,
    });
    expect(
      installKeyLimits({ expiresAt: new Date(now.getTime() + h) }, now)
        .expiresAt,
    ).toEqual(new Date(now.getTime() + h));
  });
  it('refuses less than an hour, more than 30 days, and too many uses', () => {
    for (const ms of [h - 1, 30 * 24 * h + 1, -1]) {
      expect(() =>
        installKeyLimits({ expiresAt: new Date(now.getTime() + ms) }, now),
      ).toThrow(InstallKeyLimitError);
    }
    expect(() => installKeyLimits({ maxUses: 10_001 }, now)).toThrow(
      InstallKeyLimitError,
    );
  });
  it('allows up to 365 days only for a key locked to address ranges', () => {
    const year = new Date(now.getTime() + 365 * 24 * h);
    expect(() => installKeyLimits({ expiresAt: year }, now)).toThrow(
      InstallKeyLimitError,
    );
    expect(
      installKeyLimits({ expiresAt: year, allowedCidrs: ['10.0.0.0/8'] }, now)
        .expiresAt,
    ).toEqual(year);
    expect(() =>
      installKeyLimits(
        {
          expiresAt: new Date(year.getTime() + 1),
          allowedCidrs: ['10.0.0.0/8'],
        },
        now,
      ),
    ).toThrow(InstallKeyLimitError);
  });
});
