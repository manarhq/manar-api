import { describe, expect, it } from 'vitest';
import {
  assertSafeOutboundUrl,
  UnsafeOutboundUrlError,
  type DnsLookupFn,
} from './url-safety';

function fixedLookup(
  ...addresses: { address: string; family: number }[]
): DnsLookupFn {
  return () => Promise.resolve(addresses);
}

describe('assertSafeOutboundUrl', () => {
  it('accepts a URL resolving to a public address', async () => {
    await expect(
      assertSafeOutboundUrl('https://example.com/webhook', {
        lookup: fixedLookup({ address: '93.184.216.34', family: 4 }),
      }),
    ).resolves.toBeUndefined();
  });

  it.each([
    ['loopback', '127.0.0.1'],
    ['private class A', '10.1.2.3'],
    ['private class B', '172.16.5.5'],
    ['private class C', '192.168.1.1'],
    ['link-local / metadata service', '169.254.169.254'],
    ['this-network', '0.0.0.0'],
    ['carrier-grade NAT', '100.64.0.1'],
    ['multicast', '224.0.0.1'],
  ])(
    'rejects a URL resolving to a %s address (%s)',
    async (_label, address) => {
      await expect(
        assertSafeOutboundUrl('https://internal.example/', {
          lookup: fixedLookup({ address, family: 4 }),
        }),
      ).rejects.toThrow(UnsafeOutboundUrlError);
    },
  );

  it.each([
    ['loopback', '::1'],
    ['link-local', 'fe80::1'],
    ['unique-local', 'fd00::1'],
    ['IPv4-mapped private', '::ffff:10.0.0.1'],
  ])(
    'rejects a URL resolving to an IPv6 %s address (%s)',
    async (_label, address) => {
      await expect(
        assertSafeOutboundUrl('https://internal.example/', {
          lookup: fixedLookup({ address, family: 6 }),
        }),
      ).rejects.toThrow(UnsafeOutboundUrlError);
    },
  );

  it('rejects a raw private IP literal in the URL itself (no hostname to rebind)', async () => {
    await expect(
      assertSafeOutboundUrl('http://169.254.169.254/latest/meta-data/', {
        lookup: fixedLookup({ address: '169.254.169.254', family: 4 }),
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
  });

  it('rejects a non-http(s) protocol', async () => {
    await expect(
      assertSafeOutboundUrl('file:///etc/passwd', {
        lookup: fixedLookup({ address: '1.2.3.4', family: 4 }),
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
  });

  it('rejects when even one of several resolved addresses is unsafe', async () => {
    await expect(
      assertSafeOutboundUrl('https://multi.example/', {
        lookup: fixedLookup(
          { address: '93.184.216.34', family: 4 },
          { address: '127.0.0.1', family: 4 },
        ),
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
  });

  it('rejects an unresolvable hostname', async () => {
    const lookup: DnsLookupFn = () => Promise.reject(new Error('ENOTFOUND'));
    await expect(
      assertSafeOutboundUrl('https://nowhere.invalid/', { lookup }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
  });

  it('DNS rebinding: a URL that resolved safely once is rejected on a later, re-validated call once its hostname now resolves internally', async () => {
    // Simulates the exact attack the design spec calls out: a hostname
    // that resolved to a public address at registration time is
    // repointed (e.g. by an attacker controlling its DNS) to an internal
    // address by the time of a later, real request. A caller that only
    // validated once at registration would never catch this -- this
    // function is designed to be called fresh at *every* use, and this
    // test proves that a second call against the same URL, backed by a
    // resolver whose answer changed, is what actually catches it.
    let call = 0;
    const rebindingLookup: DnsLookupFn = () => {
      call += 1;
      return Promise.resolve(
        call === 1
          ? [{ address: '93.184.216.34', family: 4 }] // safe, first (registration-time) call
          : [{ address: '169.254.169.254', family: 4 }], // rebound, later (call-time) lookup
      );
    };

    // Registration-time check: passes.
    await expect(
      assertSafeOutboundUrl('https://rebinding.example/', {
        lookup: rebindingLookup,
      }),
    ).resolves.toBeUndefined();

    // Call-time re-validation, same URL: now rejected.
    await expect(
      assertSafeOutboundUrl('https://rebinding.example/', {
        lookup: rebindingLookup,
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
  });

  describe('allowedHosts (SSRF_ALLOWED_HOSTS operator exception list)', () => {
    it('an allow-listed hostname skips the range check entirely, even though it resolves to a private address', async () => {
      await expect(
        assertSafeOutboundUrl('http://127.0.0.1:4000/hook', {
          lookup: fixedLookup({ address: '127.0.0.1', family: 4 }),
          allowedHosts: new Set(['127.0.0.1']),
        }),
      ).resolves.toBeUndefined();
    });

    it('a hostname NOT on the allow-list is still rejected as usual', async () => {
      await expect(
        assertSafeOutboundUrl('http://127.0.0.1:4000/hook', {
          lookup: fixedLookup({ address: '127.0.0.1', family: 4 }),
          allowedHosts: new Set(['some-other-allowed-host']),
        }),
      ).rejects.toThrow(UnsafeOutboundUrlError);
    });

    it('the allow-list still requires an allowed protocol', async () => {
      await expect(
        assertSafeOutboundUrl('file:///etc/passwd', {
          allowedHosts: new Set(['']), // an empty hostname is what file:// URLs parse to
        }),
      ).rejects.toThrow(UnsafeOutboundUrlError);
    });
  });
});
