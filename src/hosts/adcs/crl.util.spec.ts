import 'reflect-metadata';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  makeCa,
  makeCrl,
  makeLeaf,
  type TestCa,
} from '../../../test/support/test-pki';
import { checkRevocation } from './crl.util';

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
});
