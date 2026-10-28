import 'reflect-metadata';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startLdapsServer } from '../../../test/support/ldaps-server';
import { makeCa, makeLeaf, type TestCa } from '../../../test/support/test-pki';
import * as x509 from '@peculiar/x509';
import {
  AdUnreachableError,
  isLdapsUrl,
  LdapsAdDirectory,
  type AdConnection,
} from './ad-directory.client';

describe('LdapsAdDirectory (in-process LDAPS server)', () => {
  let ca: TestCa;
  let otherCa: TestCa;
  let server: Awaited<ReturnType<typeof startLdapsServer>>;
  let base: AdConnection;
  const dir = new LdapsAdDirectory();
  const dn = 'CN=PC01,OU=Laptops,OU=Finance,DC=corp,DC=example';

  beforeAll(async () => {
    ca = await makeCa('LDAPS CA');
    otherCa = await makeCa('Wrong CA');
    const serverCert = await makeLeaf(ca, {
      dns: 'localhost',
      eku: [x509.ExtendedKeyUsage.serverAuth],
    });
    server = await startLdapsServer({
      serverCert,
      bindDn: 'CN=svc-manar,DC=corp,DC=example',
      password: 'correct horse',
      computers: [
        { dn, dNSHostName: 'pc01.corp.example' },
        { dn: 'CN=DUP1,DC=corp,DC=example', dNSHostName: 'dup.corp.example' },
        { dn: 'CN=DUP2,DC=corp,DC=example', dNSHostName: 'dup.corp.example' },
      ],
    });
    base = {
      ldapsUrl: server.url,
      baseDn: 'DC=corp,DC=example',
      bindDn: 'CN=svc-manar,DC=corp,DC=example',
      serverCaPem: ca.pem,
      password: 'correct horse',
    };
  });
  afterAll(() => server.close());

  it('reads the distinguishedName of the computer', async () => {
    expect(await dir.findComputer(base, 'pc01.corp.example')).toEqual({
      found: true,
      dn,
    });
  });

  it('reports not found, and never claims an OU for an ambiguous name', async () => {
    expect(await dir.findComputer(base, 'nobody.corp.example')).toEqual({
      found: false,
    });
    expect(await dir.findComputer(base, 'dup.corp.example')).toEqual({
      found: false,
    });
  });

  it('does not let a filter metacharacter widen the search', async () => {
    expect(await dir.findComputer(base, '*')).toEqual({ found: false });
    expect(await dir.findComputer(base, 'x)(objectClass=*')).toEqual({
      found: false,
    });
  });

  it('refuses a server certificate the configured CA did not sign', async () => {
    await expect(
      dir.findComputer(
        { ...base, serverCaPem: otherCa.pem },
        'pc01.corp.example',
      ),
    ).rejects.toBeInstanceOf(AdUnreachableError);
  });

  it('is unreachable on a bad password, a closed port, or a non-LDAPS URL', async () => {
    await expect(
      dir.findComputer({ ...base, password: 'nope' }, 'pc01.corp.example'),
    ).rejects.toBeInstanceOf(AdUnreachableError);
    await expect(
      dir.findComputer(
        { ...base, ldapsUrl: 'ldaps://localhost:1' },
        'pc01.corp.example',
      ),
    ).rejects.toBeInstanceOf(AdUnreachableError);
    await expect(
      dir.findComputer({ ...base, ldapsUrl: 'ldap://localhost:389' }, 'x'),
    ).rejects.toBeInstanceOf(AdUnreachableError);
  });

  it('error messages carry neither the password nor the bind DN', async () => {
    const err = await dir
      .findComputer({ ...base, password: 'nope' }, 'pc01.corp.example')
      .catch((e: Error) => e);
    expect(String((err as Error).message)).not.toMatch(/nope|svc-manar/);
  });

  it('isLdapsUrl accepts only ldaps with a host and no credentials', () => {
    expect(isLdapsUrl('ldaps://dc1.corp.example:636')).toBe(true);
    expect(isLdapsUrl('ldap://dc1.corp.example')).toBe(false);
    expect(isLdapsUrl('ldaps://user:pw@dc1.corp.example')).toBe(false);
    expect(isLdapsUrl('http://x')).toBe(false);
    expect(isLdapsUrl('nonsense')).toBe(false);
  });
});
