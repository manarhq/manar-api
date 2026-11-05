import { describe, expect, it } from 'vitest';
import { scopeFor, scopeMatches } from './rule-scope';

const T = 'host.cursor';
const file = (r: string) => scopeFor(T, 'edit', r);
const web = (r: string) => scopeFor(T, 'webfetch', r);
const inside = (p: string, r: string) => scopeMatches(p, T, 'edit', r);
const fetchOk = (p: string, r: string) => scopeMatches(p, T, 'webfetch', r);

describe('folder scopes are absolute, owner included', () => {
  it.each([
    ['/home/sara/proj/src/a.ts', '/home/sara/proj/src/*'],
    ['/Users/sara/proj/a.ts', '/Users/sara/proj/*'],
    ['/work/app/x.ts', '/work/app/*'],
    ['C:\\Work\\App\\x.ts', 'c:/work/app/*'],
    ['c:/Users/Sara/proj/x.ts', 'c:/users/sara/proj/*'],
    ['/home/سارة/مشروع/a.ts', '/home/سارة/مشروع/*'],
  ])('%s -> %s', (r, want) => expect(file(r)).toBe(want));

  it.each([
    ['relative', 'src/a.ts'],
    ['top-level file', '/a.ts'],
    ['home folder itself', '/home/sara/notes.txt'],
    ['dot folder under home', '/home/sara/.ssh/config'],
    ['.config under home', '/home/sara/.config/x/y.json'],
    ['root user', '/root/proj/a.ts'],
    ['system folders', '/etc/nginx/nginx.conf'],
    ['usr', '/usr/local/bin/x'],
    ['windows dir', 'c:/windows/system32/x.dll'],
    ['program files', 'C:\\Program Files\\App\\x.exe'],
    ['secret name', '/home/sara/proj/.env'],
    ['secret dir', '/home/sara/.aws/credentials'],
    ['climb', '/home/sara/proj/../omar/a.ts'],
    ['climb to other home', '/home/sara/proj/../omar/'],
    ['dot segment climb', '/home/sara/proj/src/../../x/a.ts'],
    ['UNC slash', '//server/share/proj/a.ts'],
    ['UNC backslash', '\\\\server\\share\\proj\\a.ts'],
    ['backslash in posix', '/home/sara/proj\\src/a.ts'],
    ['ADS', 'c:/work/app/a.txt:hidden'],
    ['ADS stream type', 'c:/work/app/a.txt::$DATA'],
    ['8.3 short name', 'C:\\PROGRA~1\\app\\a.ts'],
    ['8.3 in project', 'c:/work/PROJEC~1/a.ts'],
    ['trailing dot', 'c:/work/app./a.ts'],
    ['trailing space', 'c:/work/app /a.ts'],
    ['device name', 'c:/work/con/a.ts'],
    ['percent', '/home/sara/pro%2ej/a.ts'],
    ['control char', '/home/sara/proj/a\u0000.ts'],
    ['bidi override', '/home/sara/proj\u202e/a.ts'],
  ])('refuses %s', (_n, r) => expect(file(r)).toBeNull());
});

describe('folder matching', () => {
  const P = '/home/sara/proj/src/*';
  it('matches inside, on a segment boundary', () => {
    expect(inside(P, '/home/sara/proj/src/a/b.ts')).toBe(true);
    expect(inside(P, '/home/sara/proj/src-secrets/a.ts')).toBe(false);
    expect(inside(P, '/home/sara/proj/src')).toBe(false);
    expect(inside(P, '/home/sara/proj/srcx/a.ts')).toBe(false);
  });
  it('never matches another person, root, or a climb', () => {
    expect(inside(P, '/home/omar/proj/src/a.ts')).toBe(false);
    expect(inside(P, '/root/proj/src/a.ts')).toBe(false);
    expect(inside(P, '/home/sara/proj/src/../../omar/a.ts')).toBe(false);
    expect(inside(P, '/home/sara/proj/src/../x.ts')).toBe(false);
    expect(inside(P, 'proj/src/a.ts')).toBe(false);
    expect(inside(P, '/home/sara/proj/src/.env')).toBe(false);
    expect(inside(P, '/home/sara/proj/src/a%2eb')).toBe(false);
  });
  it('a pattern with no wildcard or a command never matches', () => {
    expect(inside('/home/sara/proj/src/', '/home/sara/proj/src/a.ts')).toBe(
      false,
    );
    expect(scopeMatches(P, T, 'shell', '/home/sara/proj/src/x')).toBe(false);
  });
  it('windows: case, slashes and drive letters', () => {
    const W = 'c:/work/app/*';
    expect(inside(W, 'C:\\Work\\App\\sub\\x.ts')).toBe(true);
    expect(inside(W, 'c:/WORK/app/x.ts')).toBe(true);
    expect(inside(W, 'D:\\work\\app\\x.ts')).toBe(false);
    expect(inside(W, 'c:/work/app2/x.ts')).toBe(false);
    expect(inside(W, '\\\\server\\c$\\work\\app\\x.ts')).toBe(false);
    expect(inside(W, 'c:/work/app/x.ts:stream')).toBe(false);
    expect(inside(W, 'c:/work/app./x.ts')).toBe(false);
    expect(inside(W, 'c:/work/PROJEC~1/x.ts')).toBe(false);
    expect(inside(W, 'c:/work/app/../other/x.ts')).toBe(false);
  });
  it('a posix pattern is case sensitive', () => {
    expect(inside(P, '/home/sara/PROJ/src/a.ts')).toBe(false);
  });
});

describe('web scopes need an already-canonical https URL', () => {
  it.each([
    ['https://docs.x.io/a/b?q=1', 'https://docs.x.io/*'],
    ['https://docs.x.io/', 'https://docs.x.io/*'],
    ['https://docs.x.io:8443/a', 'https://docs.x.io:8443/*'],
    ['https://a-b.example.co.uk/x', 'https://a-b.example.co.uk/*'],
  ])('%s -> %s', (r, want) => expect(web(r)).toBe(want));

  it.each([
    ['http', 'http://x.io/a'],
    ['no path', 'https://x.io'],
    ['userinfo', 'https://good.com@evil.com/'],
    ['userinfo password', 'https://good.com:pw@evil.com/'],
    ['backslash trick', 'https://good.com\\@evil.com'],
    ['backslash path', 'https://good.com\\evil/'],
    ['encoded dot host', 'https://good.com%2eevil.com/'],
    ['encoded host', 'https://g%6fod.com/'],
    ['upper-case host', 'https://Good.com/'],
    ['upper-case scheme', 'HTTPS://good.com/'],
    ['trailing dot host', 'https://good.com./'],
    ['punycode', 'https://xn--e1afmkfd.xn--p1ai/'],
    ['IDN', 'https://пример.рф/'],
    ['mixed script', 'https://goоd.com/'],
    ['default port written', 'https://good.com:443/'],
    ['port zero', 'https://good.com:0/'],
    ['ipv6', 'https://[::1]/'],
    ['whitespace', 'https://good.com/a b'],
    ['tab', 'https://good.com\t/'],
    ['newline', 'https://good.com/\n'],
    ['control char', 'https://good.com/\u0001'],
    ['leading space', ' https://good.com/'],
    ['empty host', 'https:///a'],
    ['double dot host', 'https://good..com/'],
  ])('refuses %s', (_n, r) => expect(web(r)).toBeNull());

  it('matches only the same canonical origin', () => {
    const P = 'https://good.com/*';
    expect(fetchOk(P, 'https://good.com/a?b=c')).toBe(true);
    for (const r of [
      'https://good.com@evil.com/',
      'https://good.com\\@evil.com',
      'https://good.com%2eevil.com',
      'https://good.com%2eevil.com/',
      'https://good.com.evil.com/',
      'https://evilgood.com/',
      'https://good.com:8443/',
      'http://good.com/',
      'https://good.com',
      'https://GOOD.com/',
      'https://good.com/\u0000',
    ])
      expect(fetchOk(P, r)).toBe(false);
    expect(fetchOk('https://good.com:8443/*', 'https://good.com:8443/x')).toBe(
      true,
    );
    expect(fetchOk('https://good.com:8443/*', 'https://good.com/x')).toBe(
      false,
    );
  });
});

describe('mcp and commands', () => {
  it('mcp exactly, never a wildcard; commands have no scope', () => {
    expect(scopeFor(T, 'mcp', 'github/create_issue')).toBe(
      'github/create_issue',
    );
    expect(scopeFor(T, 'mcp', 'github/*')).toBeNull();
    expect(
      scopeMatches('github/create_issue', T, 'mcp', 'github/create_issue'),
    ).toBe(true);
    expect(
      scopeMatches('github/create_issue', T, 'mcp', 'github/delete_repo'),
    ).toBe(false);
    expect(scopeFor(T, 'shell', 'ls -la')).toBeNull();
  });
});
