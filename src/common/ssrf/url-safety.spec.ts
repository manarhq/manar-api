import { ssrfPolicyFromConfig } from './ssrf.config';
import { describe, expect, it } from 'vitest';
import {
  assertSafeOutboundUrl,
  OutboundResponseTooLargeError,
  readBoundedResponseText,
  safeOutboundFetch,
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

  describe('S1: IPv4-mapped IPv6 in the hex form the URL parser produces', () => {
    it.each([
      'http://[::ffff:127.0.0.1]:6379/',
      'http://[::ffff:7f00:1]:6379/',
      'http://[::ffff:a9fe:a9fe]/latest/meta-data/',
      'http://[::7f00:1]/',
      'http://[64:ff9b::a9fe:a9fe]/',
      'http://[::ffff:a00:1]/',
    ])('rejects %s', async (url) => {
      await expect(assertSafeOutboundUrl(url)).rejects.toThrow(
        UnsafeOutboundUrlError,
      );
    });
  });

  describe('allowedHosts (SSRF_ALLOWED_HOSTS operator exception list)', () => {
    it('an allow-listed hostname may resolve to a private address', async () => {
      await expect(
        assertSafeOutboundUrl('http://siem.internal:4000/hook', {
          lookup: fixedLookup({ address: '10.1.2.3', family: 4 }),
          allowedHosts: new Set(['siem.internal']),
        }),
      ).resolves.toBeUndefined();
    });

    it('an allow-listed hostname may resolve to loopback only with allowLoopback (development)', async () => {
      const options = {
        lookup: fixedLookup({ address: '127.0.0.1', family: 4 }),
        allowedHosts: new Set(['localhost']),
      };
      await expect(
        assertSafeOutboundUrl('http://localhost:4000/hook', options),
      ).rejects.toThrow(UnsafeOutboundUrlError);
      await expect(
        assertSafeOutboundUrl('http://localhost:4000/hook', {
          ...options,
          allowLoopback: true,
        }),
      ).resolves.toBeUndefined();
    });

    it('S2: an allow-listed hostname that resolves to the metadata service is rejected, even with allowLoopback', async () => {
      await expect(
        assertSafeOutboundUrl('http://tools.internal/latest/meta-data/', {
          lookup: fixedLookup({ address: '169.254.169.254', family: 4 }),
          allowedHosts: new Set(['tools.internal']),
          allowLoopback: true,
        }),
      ).rejects.toThrow(UnsafeOutboundUrlError);
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

/**
 * A minimal in-memory `fetch` stand-in: a scripted list of responses (one
 * per hop) plus a record of exactly what each hop was asked to send, so a
 * test can assert on the *request* — which URL, which method, which
 * headers — and not merely on whether the call resolved. Deliberately not
 * a `vi.stubGlobal` on the real `fetch`: `safeOutboundFetch` takes an
 * injectable one for exactly this reason, and injecting it keeps the test
 * free of global state.
 */
function scriptedFetch(
  hops: {
    status: number;
    location?: string;
    body?: string;
    headers?: Record<string, string>;
  }[],
): {
  fetchImpl: typeof fetch;
  requests: { url: string; method: string; headers: Record<string, string> }[];
} {
  const requests: {
    url: string;
    method: string;
    headers: Record<string, string>;
  }[] = [];
  let index = 0;

  const fetchImpl = ((input: string | URL | Request, init?: RequestInit) => {
    requests.push({
      url: typeof input === 'string' ? input : requestedUrl(input),
      method: init?.method ?? 'GET',
      headers: { ...((init?.headers ?? {}) as Record<string, string>) },
    });
    const hop = hops[index];
    index += 1;
    if (!hop) {
      return Promise.reject(
        new Error(`scriptedFetch ran out of responses at hop ${index}`),
      );
    }
    const headers = new Headers(hop.headers ?? {});
    if (hop.location) headers.set('location', hop.location);
    return Promise.resolve(
      new Response(hop.body ?? null, { status: hop.status, headers }),
    );
  }) as typeof fetch;

  return { fetchImpl, requests };
}

/** `safeOutboundFetch` always passes a plain string, but `fetch`'s own signature is wider — this narrows the other two shapes without a `String(...)` that would stringify a `Request` as `[object Object]`. */
function requestedUrl(input: URL | Request): string {
  return input instanceof URL ? input.href : input.url;
}

/** Every hostname below is fictional, so the resolver is scripted per host rather than hitting real DNS. */
const hostAddresses: Record<string, string> = {
  'tool.example.test': '93.184.216.34',
  'attacker.example.test': '198.51.100.7',
  'redirector.example.test': '203.0.113.9',
  '169.254.169.254': '169.254.169.254',
  'metadata.example.test': '169.254.169.254',
};

const scriptedLookup: DnsLookupFn = (hostname) => {
  const address = hostAddresses[hostname];
  return address
    ? Promise.resolve([{ address, family: 4 }])
    : Promise.reject(new Error(`ENOTFOUND ${hostname}`));
};

describe('safeOutboundFetch', () => {
  const baseOptions = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer broker-issued-credential',
    },
    body: '{"resource":"alerts"}',
    lookup: scriptedLookup,
  };

  it('returns a non-redirect response without following anything', async () => {
    const { fetchImpl, requests } = scriptedFetch([
      { status: 200, body: '{"ok":true}' },
    ]);

    const response = await safeOutboundFetch('https://tool.example.test/run', {
      ...baseOptions,
      fetchImpl,
    });

    expect(response.status).toBe(200);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.method).toBe('POST');
  });

  it('never lets the runtime follow redirects on its own', async () => {
    const { fetchImpl } = scriptedFetch([{ status: 200 }]);
    let observedRedirectMode: RequestRedirect | undefined;
    const recordingFetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      observedRedirectMode = init?.redirect;
      return fetchImpl(input, init);
    }) as typeof fetch;

    await safeOutboundFetch('https://tool.example.test/run', {
      ...baseOptions,
      fetchImpl: recordingFetch,
    });

    expect(observedRedirectMode).toBe('manual');
  });

  it('blocks a redirect to the cloud instance metadata service', async () => {
    // The bypass this whole helper exists for: the registered host passes
    // every check, and then answers with a Location pointing at
    // 169.254.169.254. Under the runtime's default `redirect: "follow"`
    // that request is made inside undici with no application-level check
    // on the target at all.
    const { fetchImpl, requests } = scriptedFetch([
      { status: 302, location: 'http://169.254.169.254/latest/meta-data/' },
      { status: 200, body: 'SECRET_ACCESS_KEY' },
    ]);

    await expect(
      safeOutboundFetch('https://tool.example.test/run', {
        ...baseOptions,
        fetchImpl,
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);

    // The metadata service was never contacted.
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe('https://tool.example.test/run');
  });

  it('blocks a redirect to a hostname that resolves to the metadata service', async () => {
    const { fetchImpl, requests } = scriptedFetch([
      { status: 307, location: 'https://metadata.example.test/latest/' },
      { status: 200, body: 'SECRET_ACCESS_KEY' },
    ]);

    await expect(
      safeOutboundFetch('https://tool.example.test/run', {
        ...baseOptions,
        fetchImpl,
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
    expect(requests).toHaveLength(1);
  });

  it('blocks a redirect to a non-http(s) scheme', async () => {
    const { fetchImpl, requests } = scriptedFetch([
      { status: 302, location: 'file:///etc/passwd' },
      { status: 200 },
    ]);

    await expect(
      safeOutboundFetch('https://tool.example.test/run', {
        ...baseOptions,
        fetchImpl,
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
    expect(requests).toHaveLength(1);
  });

  it('drops the Authorization header on a cross-origin redirect', async () => {
    // Both hosts are perfectly routable public addresses, so nothing here
    // is blocked -- the only thing standing between a redirecting tool
    // endpoint and the broker-issued credential is this header rule.
    const { fetchImpl, requests } = scriptedFetch([
      { status: 302, location: 'https://attacker.example.test/collect' },
      { status: 200, body: '{}' },
    ]);

    const response = await safeOutboundFetch('https://tool.example.test/run', {
      ...baseOptions,
      fetchImpl,
    });

    expect(response.status).toBe(200);
    expect(requests).toHaveLength(2);
    expect(requests[0]?.headers.Authorization).toBe(
      'Bearer broker-issued-credential',
    );
    expect(requests[1]?.url).toBe('https://attacker.example.test/collect');
    expect(Object.keys(requests[1]?.headers ?? {})).not.toContain(
      'Authorization',
    );
  });

  it('drops a GitLab PRIVATE-TOKEN header on a cross-origin redirect', async () => {
    const { fetchImpl, requests } = scriptedFetch([
      { status: 302, location: 'https://attacker.example.test/collect' },
      { status: 200, body: '{}' },
    ]);

    await safeOutboundFetch('https://tool.example.test/run', {
      method: 'GET',
      headers: { 'PRIVATE-TOKEN': 'glpat-broker-issued' },
      lookup: scriptedLookup,
      fetchImpl,
    });

    expect(requests[0]?.headers['PRIVATE-TOKEN']).toBe('glpat-broker-issued');
    expect(JSON.stringify(requests[1]?.headers)).not.toContain(
      'glpat-broker-issued',
    );
  });

  it('drops the Authorization header on a same-host, different-scheme redirect', async () => {
    const { fetchImpl, requests } = scriptedFetch([
      { status: 302, location: 'http://tool.example.test/run' },
      { status: 200, body: '{}' },
    ]);

    await safeOutboundFetch('https://tool.example.test/run', {
      ...baseOptions,
      fetchImpl,
    });

    expect(Object.keys(requests[1]?.headers ?? {})).not.toContain(
      'Authorization',
    );
  });

  it.each([307, 308])(
    'S2: refuses a cross-origin %i, which would replay the agent-supplied body to another origin',
    async (status) => {
      const { fetchImpl, requests } = scriptedFetch([
        { status, location: 'https://attacker.example.test/collect' },
        { status: 200, body: '{}' },
      ]);

      await expect(
        safeOutboundFetch('https://tool.example.test/run', {
          ...baseOptions,
          fetchImpl,
        }),
      ).rejects.toThrow(UnsafeOutboundUrlError);
      expect(requests).toHaveLength(1);
    },
  );

  it('S2: does not apply the allowlist to redirect hops', async () => {
    const { fetchImpl, requests } = scriptedFetch([
      { status: 302, location: 'http://siem.internal/' },
      { status: 200, body: '{}' },
    ]);

    await expect(
      safeOutboundFetch('https://tool.example.test/run', {
        ...baseOptions,
        fetchImpl,
        allowedHosts: new Set(['siem.internal']),
        lookup: (host) =>
          Promise.resolve([
            {
              address: host === 'siem.internal' ? '10.0.0.5' : '203.0.113.10',
              family: 4,
            },
          ]),
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
    expect(requests).toHaveLength(1);
  });

  it('keeps the Authorization header on a same-origin redirect', async () => {
    const { fetchImpl, requests } = scriptedFetch([
      { status: 307, location: '/run/v2' },
      { status: 200, body: '{}' },
    ]);

    await safeOutboundFetch('https://tool.example.test/run', {
      ...baseOptions,
      fetchImpl,
    });

    expect(requests[1]?.url).toBe('https://tool.example.test/run/v2');
    expect(requests[1]?.headers.Authorization).toBe(
      'Bearer broker-issued-credential',
    );
  });

  it('preserves method and body across a 307, and rewrites a 303 to a bodiless GET', async () => {
    const preserving = scriptedFetch([
      { status: 307, location: '/run/v2' },
      { status: 200 },
    ]);
    await safeOutboundFetch('https://tool.example.test/run', {
      ...baseOptions,
      fetchImpl: preserving.fetchImpl,
    });
    expect(preserving.requests[1]?.method).toBe('POST');

    const rewriting = scriptedFetch([
      { status: 303, location: '/result/1' },
      { status: 200 },
    ]);
    await safeOutboundFetch('https://tool.example.test/run', {
      ...baseOptions,
      fetchImpl: rewriting.fetchImpl,
    });
    expect(rewriting.requests[1]?.method).toBe('GET');
    expect(Object.keys(rewriting.requests[1]?.headers ?? {})).not.toContain(
      'Content-Type',
    );
  });

  it('gives up once the redirect chain exceeds the hop limit', async () => {
    const { fetchImpl, requests } = scriptedFetch(
      Array.from({ length: 8 }, () => ({
        status: 302,
        location: 'https://redirector.example.test/next',
      })),
    );

    await expect(
      safeOutboundFetch('https://redirector.example.test/start', {
        ...baseOptions,
        fetchImpl,
        maxRedirects: 2,
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
    expect(requests).toHaveLength(3); // the initial request plus two hops
  });

  it('hands back a 3xx that carries no Location rather than following anything', async () => {
    const { fetchImpl, requests } = scriptedFetch([{ status: 304 }]);

    const response = await safeOutboundFetch('https://tool.example.test/run', {
      ...baseOptions,
      fetchImpl,
    });

    expect(response.status).toBe(304);
    expect(requests).toHaveLength(1);
  });

  it('still rejects the very first URL when it is unsafe', async () => {
    const { fetchImpl, requests } = scriptedFetch([{ status: 200 }]);

    await expect(
      safeOutboundFetch('http://169.254.169.254/latest/meta-data/', {
        ...baseOptions,
        fetchImpl,
      }),
    ).rejects.toThrow(UnsafeOutboundUrlError);
    expect(requests).toHaveLength(0);
  });
});

describe('readBoundedResponseText', () => {
  it('reads a body that fits within the budget', async () => {
    const response = new Response('{"ok":true}');
    await expect(readBoundedResponseText(response, 1024)).resolves.toBe(
      '{"ok":true}',
    );
  });

  it('rejects a body whose declared Content-Length already exceeds the budget', async () => {
    const response = new Response('x'.repeat(50), {
      headers: { 'content-length': '50' },
    });
    await expect(readBoundedResponseText(response, 10)).rejects.toThrow(
      OutboundResponseTooLargeError,
    );
  });

  it('rejects a body that exceeds the budget while streaming, whatever the headers claimed', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('x'.repeat(64)));
        controller.enqueue(new TextEncoder().encode('x'.repeat(64)));
        controller.close();
      },
    });
    const response = new Response(stream);

    await expect(readBoundedResponseText(response, 100)).rejects.toThrow(
      OutboundResponseTooLargeError,
    );
  });

  it('returns an empty string for a body-less response', async () => {
    await expect(
      readBoundedResponseText(new Response(null, { status: 204 })),
    ).resolves.toBe('');
  });
});

describe('ssrfPolicyFromConfig', () => {
  it('refuses to boot with SSRF_ALLOW_LOOPBACK in production', () => {
    const config = {
      get: (key: string) =>
        ({
          SSRF_ALLOW_LOOPBACK: true,
          NODE_ENV: 'production',
          SSRF_ALLOWED_HOSTS: '',
        })[key],
    } as unknown as Parameters<typeof ssrfPolicyFromConfig>[0];
    expect(() => ssrfPolicyFromConfig(config)).toThrow(/refused/);
  });
});
