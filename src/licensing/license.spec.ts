import { execFileSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  evaluate,
  loadTrustAnchors,
  verifyLicense,
  type Usage,
} from './license';
import { DAY, NOW, payload, signLicense, testKeys } from './license.fakes';

const k = testKeys();
const { keys } = loadTrustAnchors(k.dir);
const nowSec = NOW.getTime() / 1000;
const usage: Usage = { agents: 3, tenants: 1 };
const check = (token: string | undefined, u: Usage = usage) =>
  evaluate(verifyLicense(token, keys), u, NOW, 'customer');
const signed = (over = {}) => signLicense(payload(over), k.privateKey, k.kid);

describe('licence verification', () => {
  it('valid: signed by a shipped key, in date, under its limits', () => {
    const s = check(signed());
    expect(s).toMatchObject({
      status: 'valid',
      reason: null,
      kid: 'test-kid',
      licenseId: 'LIC-TEST-1',
      customer: 'Test customer',
      deployment: 'customer',
      daysLeft: 200,
      limits: { agents: 10, tenants: 1 },
      usage,
      overLimit: [],
      features: ['packs'],
    });
    expect(s.expiresAt).toBe(
      new Date((nowSec + 200 * DAY) * 1000).toISOString(),
    );
  });

  it('expired at exp, with negative days left', () => {
    expect(check(signed({ exp: nowSec })).status).toBe('expired');
    expect(check(signed({ exp: nowSec - 3 * DAY }))).toMatchObject({
      status: 'expired',
      daysLeft: -3,
    });
  });

  it('expiring inside 30 days, valid just outside', () => {
    expect(check(signed({ exp: nowSec + 30 * DAY })).status).toBe('expiring');
    expect(check(signed({ exp: nowSec + 1 })).status).toBe('expiring');
    expect(check(signed({ exp: nowSec + 30 * DAY + 1 })).status).toBe('valid');
  });

  it('not yet valid when nbf is in the future, beyond five minutes of clock skew', () => {
    expect(check(signed({ nbf: nowSec + DAY })).status).toBe('not_yet_valid');
    expect(check(signed({ nbf: nowSec + 60 })).status).toBe('valid');
  });

  it('over limit: usage above a licensed amount, never at it', () => {
    expect(check(signed(), { agents: 11, tenants: 1 })).toMatchObject({
      status: 'over_limit',
      overLimit: ['agents'],
    });
    expect(check(signed(), { agents: 10, tenants: 2 }).overLimit).toEqual([
      'tenants',
    ]);
    expect(check(signed(), { agents: 10, tenants: 1 }).status).toBe('valid');
  });

  it('over limit wins over expiring; expired wins over both', () => {
    const over: Usage = { agents: 99, tenants: 1 };
    expect(check(signed({ exp: nowSec + DAY }), over).status).toBe(
      'over_limit',
    );
    expect(check(signed({ exp: nowSec - DAY }), over).status).toBe('expired');
  });

  it('a null limit is unlimited, and unknown usage is never over a limit', () => {
    const unlimited = signed({ limits: { agents: null, tenants: null } });
    expect(check(unlimited, { agents: 1e6, tenants: 500 }).status).toBe(
      'valid',
    );
    expect(check(signed(), { agents: null, tenants: null }).status).toBe(
      'valid',
    );
  });

  it('bad signature: a payload changed after signing', () => {
    const [h, , sig] = signed().split('.');
    const tampered = Buffer.from(
      JSON.stringify(payload({ limits: { agents: null, tenants: null } })),
    ).toString('base64url');
    const s = check(`${h}.${tampered}.${sig}`);
    expect(s).toMatchObject({
      status: 'invalid_signature',
      reason: 'bad_signature',
    });
    // Nothing from an untrusted payload is reported as a claim.
    expect(s.licenseId).toBeNull();
    expect(s.limits).toBeNull();
    expect(s.expiresAt).toBeNull();
  });

  it('bad signature: signed by a key with a shipped kid but not its private half', () => {
    const other = generateKeyPairSync('ed25519').privateKey;
    expect(check(signLicense(payload(), other, k.kid)).reason).toBe(
      'bad_signature',
    );
  });

  it('unverifiable: a kid with no shipped public key', () => {
    const s = check(signLicense(payload(), k.privateKey, 'production-2026'));
    expect(s).toMatchObject({
      status: 'unverifiable',
      reason: 'unknown_kid',
      kid: 'production-2026',
      licenseId: null,
    });
  });

  it.each([
    ['not a JWS', 'hello'],
    ['two parts', 'a.b'],
    ['non base64url', 'a.b+c.d'],
    ['bad JSON', 'e30.bm90LWpzb24.c2ln'],
    [
      'wrong alg',
      signed().replace(
        /^[^.]+/,
        Buffer.from('{"alg":"HS256","kid":"test-kid"}').toString('base64url'),
      ),
    ],
    ['schema', signLicense({ ...payload(), v: 2 }, k.privateKey, k.kid)],
    ['negative limit', signed({ limits: { agents: -1, tenants: 1 } })],
  ])('malformed: %s', (_, token) => {
    expect(check(token)).toMatchObject({
      status: 'invalid_signature',
      reason: 'malformed',
    });
  });

  it('missing: no licence configured, deployment from config', () => {
    expect(check(undefined)).toMatchObject({ status: 'missing', reason: null });
    expect(check('  \n')).toMatchObject({ status: 'missing' });
    const hosted = evaluate(
      verifyLicense(undefined, keys),
      usage,
      NOW,
      'hosted',
    );
    expect(hosted.deployment).toBe('hosted');
  });

  it('a verified licence states the deployment, whatever the config says', () => {
    const s = evaluate(verifyLicense(signed(), keys), usage, NOW, 'hosted');
    expect(s.deployment).toBe('customer');
  });
});

describe('trust anchors', () => {
  it('loads Ed25519 keys by kid and skips anything else', () => {
    const dir = testKeys('good').dir;
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
    writeFileSync(
      join(dir, 'rsa.pub'),
      rsa.export({ type: 'spki', format: 'pem' }),
    );
    writeFileSync(join(dir, 'junk.pub'), 'not a key');
    writeFileSync(join(dir, 'notes.txt'), 'ignored');
    const { keys: loaded, skipped } = loadTrustAnchors(dir);
    expect([...loaded.keys()]).toEqual(['good']);
    expect(skipped.sort()).toEqual(['junk.pub', 'rsa.pub']);
  });

  it('a missing directory means no anchors, not an error', () => {
    expect(loadTrustAnchors('/nonexistent/manar').keys.size).toBe(0);
  });

  it('ships no production key yet: every licence is unverifiable until one is added by MR', () => {
    // When the founder adds src/licensing/keys/<kid>.pub, update this test.
    expect(loadTrustAnchors(join(__dirname, 'keys')).keys.size).toBe(0);
  });
});

describe('scripts/license-issue.mjs', () => {
  it('issues a licence this verifier accepts, reading the key from stdin', () => {
    const pem = k.privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const out = execFileSync(
      process.execPath,
      [
        join(__dirname, '../../scripts/license-issue.mjs'),
        '--key',
        '-',
        '--kid',
        k.kid,
        '--lic',
        'LIC-0001',
        '--sub',
        'Customer name',
        '--deployment',
        'customer',
        '--expires',
        '2099-01-01',
        '--agents',
        '50',
        '--features',
        'packs, watcher',
      ],
      { input: pem, encoding: 'utf8' },
    ).trim();
    const v = verifyLicense(out, keys);
    expect(v.result).toBe('verified');
    expect('payload' in v && v.payload).toMatchObject({
      lic: 'LIC-0001',
      sub: 'Customer name',
      limits: { agents: 50, tenants: null },
      features: ['packs', 'watcher'],
      exp: Date.parse('2099-01-01T00:00:00Z') / 1000,
    });
  });

  it('refuses bad input with exit code 2 and prints nothing to stdout', () => {
    let error: { status?: number; stdout?: string } = {};
    try {
      execFileSync(
        process.execPath,
        [join(__dirname, '../../scripts/license-issue.mjs'), '--kid', 'x'],
        { encoding: 'utf8', stdio: 'pipe' },
      );
    } catch (e) {
      error = e as typeof error;
    }
    expect(error.status).toBe(2);
    expect(error.stdout).toBe('');
  });
});
