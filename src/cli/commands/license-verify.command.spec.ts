import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  NOW,
  payload,
  signLicense,
  testKeys,
} from '../../licensing/license.fakes';
import { LicenseVerifyCommand } from './license-verify.command';

const k = testKeys();

async function run(token: string, keyDir = k.dir) {
  const file = join(k.dir, `l-${Math.random()}.jws`);
  writeFileSync(file, token);
  const out = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  const cmd = new LicenseVerifyCommand();
  cmd.keyDir = keyDir;
  await cmd.run([file]);
  return JSON.parse(String(out.mock.calls[0]![0])) as Record<string, unknown>;
}

describe('license:verify', () => {
  // Licence times in the fakes are relative to NOW.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
    process.exitCode = 0;
  });

  it('prints the payload and status, exit 0 for a valid licence', async () => {
    const out = await run(signLicense(payload(), k.privateKey, k.kid));
    expect(out).toMatchObject({
      status: 'valid',
      verified: true,
      payload: { lic: 'LIC-TEST-1' },
    });
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('shows an unverifiable licence decoded but flagged, exit 1', async () => {
    const out = await run(
      signLicense(payload(), k.privateKey, k.kid),
      '/nonexistent',
    );
    expect(out).toMatchObject({
      status: 'unverifiable',
      verified: false,
      kid: k.kid,
      payload: { lic: 'LIC-TEST-1' },
    });
    expect(process.exitCode).toBe(1);
  });
});
