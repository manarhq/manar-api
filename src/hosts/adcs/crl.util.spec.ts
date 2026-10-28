import 'reflect-metadata';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  makeCa,
  makeCrl,
  makeLeaf,
  type TestCa,
} from '../../../test/support/test-pki';
import { checkRevocation, fetchCrlHttp } from './crl.util';

describe('checkRevocation', () => {
  let ca: TestCa;
  let other: TestCa;
  beforeAll(async () => {
    ca = await makeCa('CRL CA');
    other = await makeCa('Other CRL CA');
  });
  const url = 'http://pki.corp.example/ca.crl';

  it('good when the CRL lists other serials', async () => {
    const leaf = await makeLeaf(ca, { crlUrl: url, serial: '0a01' });
    const crl = await makeCrl(ca, ['0bbb']);
    expect(
      await checkRevocation(leaf.cert, ca.cert, () => Promise.resolve(crl)),
    ).toBe('good');
  });

  it('revoked when listed', async () => {
    const leaf = await makeLeaf(ca, { crlUrl: url, serial: '0a02' });
    const crl = await makeCrl(ca, ['0a02']);
    expect(
      await checkRevocation(leaf.cert, ca.cert, () => Promise.resolve(crl)),
    ).toBe('revoked');
  });

  it('unknown when there is no distribution point', async () => {
    const leaf = await makeLeaf(ca);
    expect(
      await checkRevocation(leaf.cert, ca.cert, () =>
        Promise.resolve(new Uint8Array()),
      ),
    ).toBe('unknown');
  });

  it('unknown when the CRL is unreachable', async () => {
    const leaf = await makeLeaf(ca, { crlUrl: url });
    expect(
      await checkRevocation(leaf.cert, ca.cert, () =>
        Promise.reject(new Error('ECONNREFUSED')),
      ),
    ).toBe('unknown');
  });

  it('unknown when the CRL is stale, foreign-signed, or garbage', async () => {
    const leaf = await makeLeaf(ca, { crlUrl: url, serial: '0a03' });
    const stale = await makeCrl(ca, ['0a03'], {
      nextUpdate: new Date(Date.now() - 1000),
    });
    expect(
      await checkRevocation(leaf.cert, ca.cert, () => Promise.resolve(stale)),
    ).toBe('unknown');
    const foreign = await makeCrl(other, ['0a03']);
    expect(
      await checkRevocation(leaf.cert, ca.cert, () => Promise.resolve(foreign)),
    ).toBe('unknown');
    expect(
      await checkRevocation(leaf.cert, ca.cert, () =>
        Promise.resolve(new Uint8Array([1, 2, 3])),
      ),
    ).toBe('unknown');
  });

  it('ignores non-HTTP distribution points', async () => {
    const leaf = await makeLeaf(ca, { crlUrl: 'ldap:///CN=x,DC=corp' });
    expect(
      await checkRevocation(leaf.cert, ca.cert, () => makeCrl(ca, [])),
    ).toBe('unknown');
  });

  describe('fetchCrlHttp', () => {
    const pub = () =>
      Promise.resolve([{ address: '93.184.216.34', family: 4 as const }]);
    const opts = (fetchImpl: typeof fetch, extra = {}) => ({
      fetchImpl,
      lookup: pub,
      ...extra,
    });

    it('returns the body of a normal response', async () => {
      const got = await fetchCrlHttp(
        'http://pki.example/ca.crl',
        opts(() => Promise.resolve(new Response(new Uint8Array([1, 2, 3])))),
      );
      expect([...got]).toEqual([1, 2, 3]);
    });

    it('refuses by Content-Length without reading the body', async () => {
      let pulled = false;
      const body = new ReadableStream(
        {
          pull() {
            pulled = true;
          },
        },
        { highWaterMark: 0 },
      );
      await expect(
        fetchCrlHttp(
          'http://pki.example/ca.crl',
          opts(
            () =>
              Promise.resolve(
                new Response(body, { headers: { 'content-length': '999999' } }),
              ),
            { maxBytes: 1000 },
          ),
        ),
      ).rejects.toThrow('too large');
      expect(pulled).toBe(false);
    });

    it('stops reading a stream that lies about its size, and cancels it', async () => {
      let produced = 0;
      let cancelled = false;
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          produced += 1000;
          controller.enqueue(new Uint8Array(1000));
        },
        cancel() {
          cancelled = true;
        },
      });
      await expect(
        fetchCrlHttp(
          'http://pki.example/ca.crl',
          opts(() => Promise.resolve(new Response(body)), { maxBytes: 5000 }),
        ),
      ).rejects.toThrow('too large');
      expect(cancelled).toBe(true);
      expect(produced).toBeLessThan(20_000);
    });

    it('times out', async () => {
      const hang: typeof fetch = (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new Error('aborted')),
          );
        });
      await expect(
        fetchCrlHttp(
          'http://pki.example/ca.crl',
          opts(hang, { timeoutMs: 50 }),
        ),
      ).rejects.toThrow();
    });

    it('refuses private and loopback targets, redirects and non-http schemes', async () => {
      const never = () => Promise.reject(new Error('must not fetch'));
      await expect(
        fetchCrlHttp('http://127.0.0.1/ca.crl', { fetchImpl: never }),
      ).rejects.toThrow();
      await expect(
        fetchCrlHttp('http://169.254.169.254/x', { fetchImpl: never }),
      ).rejects.toThrow();
      await expect(
        fetchCrlHttp('file:///etc/passwd', { fetchImpl: never }),
      ).rejects.toThrow();
      await expect(
        fetchCrlHttp(
          'http://pki.example/ca.crl',
          opts(() =>
            Promise.resolve(
              new Response(null, {
                status: 302,
                headers: { location: 'http://169.254.169.254/' },
              }),
            ),
          ),
        ),
      ).rejects.toThrow();
    });

    it('an allow-listed internal PKI host is permitted', async () => {
      const got = await fetchCrlHttp('http://pki.corp.internal/ca.crl', {
        fetchImpl: () => Promise.resolve(new Response(new Uint8Array([9]))),
        lookup: () =>
          Promise.resolve([{ address: '10.0.0.5', family: 4 as const }]),
        policy: {
          allowedHosts: new Set(['pki.corp.internal']),
          allowLoopback: false,
        },
      });
      expect([...got]).toEqual([9]);
    });

    it('too large / timeout / unreachable make revocation unknown (fail closed)', async () => {
      const leaf = await makeLeaf(ca, { crlUrl: url });
      for (const fetchImpl of [
        () => Promise.resolve(new Response(new Uint8Array(100))),
        () => Promise.reject(new Error('ECONNREFUSED')),
      ] as (typeof fetch)[]) {
        expect(
          await checkRevocation(leaf.cert, ca.cert, (u) =>
            fetchCrlHttp(u, opts(fetchImpl, { maxBytes: 10 })),
          ),
        ).toBe('unknown');
      }
    });
  });
});
