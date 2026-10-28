import { describe, expect, it } from 'vitest';
import {
  generateInstallKey,
  hashInstallKey,
  ipAllowed,
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
});
