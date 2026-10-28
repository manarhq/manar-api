import { describe, expect, it } from 'vitest';
import {
  dnUnder,
  escapeLdapFilter,
  longestOuMatch,
  normalizeDn,
} from './ou.util';

describe('ou.util', () => {
  it('normalises case and spacing', () => {
    expect(normalizeDn('CN=PC01 , OU=Finance,DC=Corp, DC=Example')).toBe(
      'cn=pc01,ou=finance,dc=corp,dc=example',
    );
  });

  it('rejects malformed DNs', () => {
    expect(normalizeDn('nonsense')).toBeNull();
    expect(normalizeDn('CN=a,')).toBeNull();
    expect(normalizeDn('CN=a\\')).toBeNull();
  });

  it('matches suffixes on RDN boundaries only', () => {
    const dn = 'CN=PC01,OU=Laptops,OU=Finance,DC=corp,DC=example';
    expect(dnUnder(dn, 'OU=Finance,DC=corp,DC=example')).toBe(true);
    expect(dnUnder(dn, 'ou=finance, dc=CORP, dc=example')).toBe(true);
    expect(dnUnder(dn, 'DC=example')).toBe(true);
    // not a prefix of a longer RDN value
    expect(dnUnder('CN=a,OU=XFinance,DC=corp', 'OU=Finance,DC=corp')).toBe(
      false,
    );
    expect(dnUnder(dn, 'OU=Sales,DC=corp,DC=example')).toBe(false);
    expect(dnUnder('DC=corp', dn)).toBe(false);
  });

  it('keeps an escaped comma inside its value', () => {
    expect(dnUnder('CN=a,OU=Ops\\, East,DC=c', 'OU=Ops\\, East,DC=c')).toBe(
      true,
    );
    expect(dnUnder('CN=a,OU=Ops\\, East,DC=c', 'OU=East,DC=c')).toBe(false);
  });

  it('the longest matching suffix wins', () => {
    const rules = [
      { ouDn: 'DC=corp,DC=example', id: 'root' },
      { ouDn: 'OU=Finance,DC=corp,DC=example', id: 'fin' },
      { ouDn: 'OU=Laptops,OU=Finance,DC=corp,DC=example', id: 'lap' },
    ];
    const pick = (dn: string) => longestOuMatch(dn, rules)?.id ?? null;
    expect(pick('CN=a,OU=Laptops,OU=Finance,DC=corp,DC=example')).toBe('lap');
    expect(pick('CN=a,OU=Finance,DC=corp,DC=example')).toBe('fin');
    expect(pick('CN=a,OU=Sales,DC=corp,DC=example')).toBe('root');
    expect(pick('CN=a,DC=other,DC=example')).toBeNull();
  });

  it('escapes filter metacharacters', () => {
    expect(escapeLdapFilter('a*)(uid=*')).toBe('a\\2a\\29\\28uid=\\2a');
  });
});
