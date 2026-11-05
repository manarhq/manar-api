import { describe, expect, it } from 'vitest';
import { scopeFor, scopeMatches } from './rule-scope';

const T = 'host.cursor';
const file = (r: string) => scopeFor(T, 'edit', r);
const web = (r: string) => scopeFor(T, 'webfetch', r);
const inside = (p: string, r: string) => scopeMatches(p, T, 'edit', r);
const fetchOk = (p: string, r: string) => scopeMatches(p, T, 'webfetch', r);

describe('folder scopes: only a project folder inside a recognised user home', () => {
  it.each([
    ['linux', '/home/sara/proj/src/a.ts', '/home/sara/proj/src/*'],
    ['macos', '/Users/sara/proj/a.ts', '/Users/sara/proj/*'],
    ['windows', 'C:\\Users\\Sara\\Work\\App\\x.ts', 'c:/users/sara/work/app/*'],
    ['windows, other drive', 'D:/Users/Sara/proj/x.ts', 'd:/users/sara/proj/*'],
    [
      'wsl windows home',
      '/mnt/c/Users/Sara/proj/x.ts',
      '/mnt/c/users/sara/proj/*',
    ],
    [
      'wsl, upper case drive path',
      '/mnt/D/USERS/Sara/Proj/x.ts',
      '/mnt/d/users/sara/proj/*',
    ],
    ['arabic names', '/home/سارة/مشروع/a.ts', '/home/سارة/مشروع/*'],
  ])('%s: %s', (_os, r, want) => expect(file(r)).toBe(want));

  it.each([
    // not under a recognised home (allowlist: nothing else is offered)
    ['system root', '/etc/nginx/nginx.conf'],
    ['opt', '/opt/app/src/a.ts'],
    ['var', '/var/www/site/a.ts'],
    ['tmp', '/tmp/work/a.ts'],
    ['root user', '/root/proj/a.ts'],
    ['plain top-level project', '/work/app/x.ts'],
    ['windows project outside Users', 'C:\\Work\\App\\x.ts'],
    ['windows dir', 'c:/windows/system32/x.dll'],
    ['other drive windows dir', 'E:/Windows/System32/x.dll'],
    ['program files', 'C:\\Program Files\\App\\x.exe'],
    ['wsl windows dir', '/mnt/c/Windows/System32/x.dll'],
    ['wsl other mount', '/mnt/data/proj/a.ts'],
    ['wsl drive root project', '/mnt/c/work/proj/a.ts'],
    ['mac system', '/Library/Application Support/x/a.json'],
    ['mac private', '/private/var/x/a.ts'],
    ['volumes', '/Volumes/Disk/proj/a.ts'],
    ['unix home itself', '/home/sara/notes.txt'],
    ['home itself, windows', 'c:/Users/sara/notes.txt'],
    ['users root', '/Users/notes.txt'],
    ['shared profile', '/Users/Shared/proj/a.ts'],
    ['public profile', 'c:/Users/Public/proj/a.ts'],
    ['default profile', 'c:/Users/Default/proj/a.ts'],
    // config and persistence folders under a home
    ['dot folder', '/home/sara/.ssh/config'],
    ['.config', '/home/sara/.config/x/y.json'],
    ['autostart', '/home/x/.config/autostart/app.desktop'],
    ['dot folder, mac', '/Users/x/.zshrc.d/a.sh'],
    ['AppData', 'C:\\Users\\x\\AppData\\Local\\Temp\\a.ts'],
    [
      'AppData startup',
      'D:/Users/x/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/a.cmd',
    ],
    ['Start Menu', 'c:/Users/x/Start Menu/Programs/a.lnk'],
    ['Application Data', 'c:/Users/x/Application Data/a.ts'],
    ['Library', '/Users/x/Library/Preferences/a.plist'],
    ['LaunchAgents', '/Users/x/Library/LaunchAgents/a.plist'],
    ['LaunchAgents deeper', '/Users/x/proj/LaunchAgents/a.plist'],
    ['LaunchDaemons', '/Users/x/proj/launchdaemons/a.plist'],
    ['Startup anywhere', '/home/x/proj/Startup/a.sh'],
    ['Startup in name', '/home/x/proj/my-startup-scripts/a.sh'],
    ['wsl AppData', '/mnt/c/Users/x/AppData/Roaming/a.ts'],
    ['wsl startup', '/mnt/c/Users/x/proj/Startup/a.cmd'],
    // paths that cannot be trusted
    ['relative', 'src/a.ts'],
    ['top-level file', '/a.ts'],
    ['secret name', '/home/sara/proj/.env'],
    ['secret dir', '/home/sara/.aws/credentials'],
    ['climb', '/home/sara/proj/../omar/a.ts'],
    ['climb to other home', '/home/sara/proj/../omar/'],
    ['dot segment climb', '/home/sara/proj/src/../../x/a.ts'],
    ['UNC slash', '//server/share/proj/a.ts'],
    ['UNC backslash', '\\\\server\\share\\proj\\a.ts'],
    ['UNC to a home', '\\\\server\\c$\\Users\\x\\proj\\a.ts'],
    ['backslash in posix', '/home/sara/proj\\src/a.ts'],
    ['ADS', 'c:/Users/x/app/a.txt:hidden'],
    ['ADS stream type', 'c:/Users/x/app/a.txt::$DATA'],
    ['8.3 short name', 'C:\\Users\\x\\PROJEC~1\\a.ts'],
    ['8.3 user name', 'C:\\Users\\SARAHS~1\\proj\\a.ts'],
    ['trailing dot', 'c:/Users/x/app./a.ts'],
    ['trailing space', 'c:/Users/x/app /a.ts'],
    ['device name', 'c:/Users/x/con/a.ts'],
    ['percent', '/home/sara/pro%2ej/a.ts'],
    ['control char', '/home/sara/proj/a\u0000.ts'],
    ['bidi override', '/home/sara/proj\u202e/a.ts'],
  ])('refuses %s: %s', (_n, r) => expect(file(r)).toBeNull());
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
    const W = 'c:/users/sara/app/*';
    expect(inside(W, 'C:\\Users\\Sara\\App\\sub\\x.ts')).toBe(true);
    expect(inside(W, 'c:/USERS/sara/app/x.ts')).toBe(true);
    expect(inside(W, 'D:\\users\\sara\\app\\x.ts')).toBe(false);
    expect(inside(W, 'c:/users/sara/app2/x.ts')).toBe(false);
    expect(inside(W, '\\\\server\\c$\\users\\sara\\app\\x.ts')).toBe(false);
    expect(inside(W, 'c:/users/sara/app/x.ts:stream')).toBe(false);
    expect(inside(W, 'c:/users/sara/app./x.ts')).toBe(false);
    expect(inside(W, 'c:/users/sara/PROJEC~1/x.ts')).toBe(false);
    expect(inside(W, 'c:/users/sara/app/../other/x.ts')).toBe(false);
  });
  it('wsl windows homes are case-insensitive; persistence folders are never covered', () => {
    expect(
      inside('/mnt/c/users/sara/proj/*', '/mnt/C/Users/Sara/Proj/x.ts'),
    ).toBe(true);
    expect(
      inside('/mnt/c/users/sara/proj/*', '/mnt/d/users/sara/proj/x.ts'),
    ).toBe(false);
    expect(
      inside('/Users/x/proj/*', '/Users/x/proj/LaunchAgents/a.plist'),
    ).toBe(false);
    expect(inside('/home/x/proj/*', '/home/x/proj/Startup/a.sh')).toBe(false);
    expect(inside('/Users/x/proj/*', '/Users/x/proj/src/a.ts')).toBe(true);
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
