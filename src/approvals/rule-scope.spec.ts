import { describe, expect, it } from 'vitest';
import { scopeFor, scopeMatches } from './rule-scope';

const T = 'host.cursor';
describe('rule scope', () => {
  it('turns a file into its folder', () => {
    expect(scopeFor(T, 'edit', '/home/sara/proj/src/a.ts')).toBe(
      '~/proj/src/*',
    );
    expect(scopeFor(T, 'edit', 'C:\\Work\\app\\x.ts')).toBe('c:/work/app/*');
  });
  it('refuses scopes that are too broad, secret, or climbing', () => {
    expect(scopeFor(T, 'edit', '/etc/hosts')).toBeNull();
    expect(scopeFor(T, 'edit', '/home/sara/notes.txt')).toBeNull();
    expect(scopeFor(T, 'edit', '/home/sara/.ssh/config')).toBeNull();
    expect(scopeFor(T, 'edit', '/home/sara/proj/.env')).toBeNull();
    expect(scopeFor(T, 'edit', '/home/sara/proj/../../x/y.ts')).toBeNull();
    expect(scopeFor(T, 'shell', 'ls -la')).toBeNull();
  });
  it('scopes web fetches to an https origin and mcp exactly', () => {
    expect(scopeFor(T, 'webfetch', 'https://docs.x.io/a/b?q=1')).toBe(
      'https://docs.x.io/*',
    );
    expect(scopeFor(T, 'webfetch', 'http://x.io/a')).toBeNull();
    expect(scopeFor(T, 'mcp', 'github/create_issue')).toBe(
      'github/create_issue',
    );
    expect(scopeFor(T, 'mcp', 'github/*')).toBeNull();
  });
  it('matches inside the folder only, never secrets or traversal', () => {
    const p = '~/proj/src/*';
    expect(scopeMatches(p, T, 'edit', '/home/sara/proj/src/a/b.ts')).toBe(true);
    expect(scopeMatches(p, T, 'edit', '/home/sara/proj/other/b.ts')).toBe(
      false,
    );
    expect(scopeMatches(p, T, 'edit', '/home/sara/proj/src/.env')).toBe(false);
    expect(scopeMatches(p, T, 'edit', '/home/sara/proj/src/../x.ts')).toBe(
      false,
    );
    expect(scopeMatches(p, T, 'shell', '~/proj/src/x')).toBe(false);
    expect(
      scopeMatches('github/create_issue', T, 'mcp', 'github/create_issue'),
    ).toBe(true);
    expect(
      scopeMatches('https://docs.x.io/*', T, 'webfetch', 'https://docs.x.io/z'),
    ).toBe(true);
    expect(
      scopeMatches(
        'https://docs.x.io/*',
        T,
        'webfetch',
        'https://docs.x.io.evil.com/z',
      ),
    ).toBe(false);
  });
});
