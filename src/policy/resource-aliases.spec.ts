import { describe, expect, it } from 'vitest';
import {
  resourceAliases,
  resourceKindFor,
  shellWords,
} from './resource-aliases';

const secret = (r: string, kind: 'path' | 'command' = 'path') =>
  resourceAliases(r, kind).some((a) => a.startsWith('secret-file:'));

describe('resourceAliases', () => {
  it('finds secrets whatever the whitespace in a file path', () => {
    expect(secret('/home/u/my keys/.aws/credentials')).toBe(true);
    expect(secret('/home/u/.aws/credentials ')).toBe(true);
    expect(secret('/work/my shop/.env')).toBe(true);
    expect(secret('C:\\Users\\Sam Lee\\.ssh\\id_rsa')).toBe(true);
  });
  it('sees through //, /./ and .. variants', () => {
    expect(secret('/home/u//.ssh///id_rsa')).toBe(true);
    expect(secret('/home/u/./.ssh/./id_rsa')).toBe(true);
    expect(secret('/home/u/proj/../.ssh/id_rsa')).toBe(true);
    expect(secret('~/proj/../.ssh/id_rsa')).toBe(true);
    expect(secret('~//.ssh/id_rsa')).toBe(true);
  });
  it('marks a path that climbs out of its root as unsafe', () => {
    expect(resourceAliases('../../.ssh/id_rsa')).toContain(
      'unsafe-path:traversal',
    );
    expect(resourceAliases('~/../other/x')).toContain('unsafe-path:traversal');
    expect(resourceAliases('~/a/../../../etc/passwd')).toContain(
      'unsafe-path:traversal',
    );
    expect(resourceAliases('/work/shop/src/a.ts')).toEqual([]);
    expect(resourceAliases('~/a/../../../etc/passwd')).toContain(
      'unsafe-path:traversal',
    );
  });
  it('normalises Windows paths', () => {
    expect(resourceAliases('C:\\Users\\x\\.aws\\credentials')).toEqual(
      expect.arrayContaining(['~/.aws/credentials', 'secret-file:credentials']),
    );
    expect(resourceAliases('C:\\Windows\\System32\\x.dll')).toContain(
      'c:/windows/system32/x.dll',
    );
  });
  it('finds secret paths inside commands, and ignores plain words', () => {
    expect(secret('cat ~/.ssh/id_rsa', 'command')).toBe(true);
    expect(secret('cat "/home/u/.aws/credentials"', 'command')).toBe(true);
    expect(secret('cat credentials', 'command')).toBe(true); // run inside ~/.aws
    expect(secret('cat id_ed25519', 'command')).toBe(true);
    expect(secret('grep password src', 'command')).toBe(false);
  });
  it('reads commands like a shell: escapes, quotes, globs and substitution', () => {
    expect(secret('cat ~/.a\\ws/credentials', 'command')).toBe(true);
    expect(secret("cat '/home/u/.aws/credentials'", 'command')).toBe(true);
    expect(resourceAliases('cat ~/.ssh/*', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat $(echo ~/.ssh/id_rsa)', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat `echo x`', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat ~/.ssh/{id_rsa,x}', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases("echo '*' '$HOME'", 'command')).toEqual([]);
    expect(resourceAliases('echo "a b" c', 'command')).toEqual([]);
    expect(shellWords('a "b c" d\\ e;f').words).toEqual([
      'a',
      'b c',
      'd e',
      'f',
    ]);
  });
  it('resolves Windows drive paths as rooted and flags clamped ..', () => {
    expect(resourceAliases('C:\\Users\\x\\..\\..\\..\\Windows')).toContain(
      'unsafe-path:traversal',
    );
    expect(resourceAliases('c:/Users/x/../y/.aws/credentials')).toEqual(
      expect.arrayContaining(['~/.aws/credentials', 'secret-file:credentials']),
    );
    expect(resourceAliases('/../etc/passwd')).toContain(
      'unsafe-path:traversal',
    );
  });
  it('kind is scoped to the tool; unknown means path', () => {
    expect(resourceKindFor('host.claude-code', 'bash')).toBe('command');
    expect(resourceKindFor('host.claude-code', 'webfetch')).toBe('other');
    expect(resourceKindFor('host.claude-code', 'read')).toBe('path');
    expect(resourceKindFor('host.cursor', 'bash')).toBe('command');
    expect(resourceKindFor('evil.tool', 'bash')).toBe('path');
    expect(resourceKindFor('evil.tool', 'webfetch')).toBe('path');
    expect(resourceKindFor('host.claude-code', 'mystery')).toBe('path');
    expect(resourceKindFor('host.cursor', 'mystery')).toBe('path');
  });
  it('gives URLs and tool names no aliases', () => {
    expect(resourceAliases('https://example.com/.env', 'other')).toEqual([]);
  });
});
