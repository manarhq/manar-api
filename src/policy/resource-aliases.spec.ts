import { describe, expect, it } from 'vitest';
import { resourceAliases } from './resource-aliases';

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
    expect(secret('grep credentials src', 'command')).toBe(false);
  });
  it('gives URLs and tool names no aliases', () => {
    expect(resourceAliases('https://example.com/.env', 'other')).toEqual([]);
  });
});
