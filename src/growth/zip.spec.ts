import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { zip } from './zip';

describe('zip', () => {
  it('produces an archive that `unzip -t` accepts and keeps the content', () => {
    const dir = mkdtempSync(join(tmpdir(), 'zip-'));
    const file = join(dir, 'a.zip');
    writeFileSync(
      file,
      zip([
        { name: 'a.json', data: Buffer.from('{"x":1}') },
        { name: 'dir/b.json', data: Buffer.alloc(5000, 'z') },
      ]),
    );
    let out = '';
    try {
      out = execFileSync('unzip', ['-t', file]).toString();
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return; // no unzip on this machine
      throw e;
    }
    expect(out).toContain('No errors detected');
    expect(execFileSync('unzip', ['-p', file, 'a.json']).toString()).toBe(
      '{"x":1}',
    );
  });
});
