import { readFileSync } from 'node:fs';
import { Command, CommandRunner } from 'nest-commander';
import {
  TRUST_ANCHOR_DIR,
  evaluate,
  loadTrustAnchors,
  verifyLicense,
} from '../../licensing/license';

/**
 * `node dist/cli.js license:verify <file>`: prints the licence's decoded payload and its status
 * against the trust anchors shipped in this image (docs/licensing.md). Needs no secret. Limits
 * are not compared with usage here (no database read). Exits 1 unless the status is valid or
 * expiring.
 */
@Command({
  name: 'license:verify',
  arguments: '<file>',
  description: 'Verify a licence file against the shipped public keys',
})
export class LicenseVerifyCommand extends CommandRunner {
  /** Tests point this elsewhere. */
  keyDir = TRUST_ANCHOR_DIR;

  run([file]: string[]): Promise<void> {
    const token = readFileSync(file!, 'utf8');
    const v = verifyLicense(token, loadTrustAnchors(this.keyDir).keys);
    const s = evaluate(
      v,
      { agents: null, tenants: null },
      new Date(),
      'customer',
    );
    const out = {
      status: s.status,
      reason: s.reason,
      kid: s.kid,
      verified: v.result === 'verified',
      daysLeft: s.daysLeft,
      // Shown even when unverified, to diagnose a licence; trusted only when verified is true.
      payload: 'payload' in v ? v.payload : null,
    };
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    if (s.status !== 'valid' && s.status !== 'expiring') process.exitCode = 1;
    return Promise.resolve();
  }
}
