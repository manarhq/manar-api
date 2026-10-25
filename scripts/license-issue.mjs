#!/usr/bin/env node
// Issues a Manar licence: a compact JWS (EdDSA, Ed25519) printed to stdout. Offline, Node only,
// no dependencies. The private key is read from a file or from stdin (`--key -`) and is never
// written anywhere. See docs/licensing.md.
//
//   node scripts/license-issue.mjs --key - --kid manar-2026 --lic LIC-0001 \
//     --sub "Customer name" --deployment customer --expires 2027-10-31 --agents 50 --tenants 1
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const usage = `usage: license-issue.mjs --key <pem file|-> --kid <kid> --lic <id> --sub <customer>
  --deployment hosted|customer --expires <YYYY-MM-DD> [--not-before <YYYY-MM-DD>]
  [--agents <n|unlimited>] [--tenants <n|unlimited>] [--features a,b]`;

function fail(message) {
  process.stderr.write(`${message}\n${usage}\n`);
  process.exit(2);
}

let args;
try {
  ({ values: args } = parseArgs({
    options: {
      key: { type: 'string' },
      kid: { type: 'string' },
      lic: { type: 'string' },
      sub: { type: 'string' },
      deployment: { type: 'string' },
      expires: { type: 'string' },
      'not-before': { type: 'string' },
      agents: { type: 'string', default: 'unlimited' },
      tenants: { type: 'string', default: 'unlimited' },
      features: { type: 'string', default: '' },
    },
  }));
} catch (e) {
  fail(e.message);
}

for (const k of ['key', 'kid', 'lic', 'sub', 'deployment', 'expires'])
  if (!args[k]) fail(`--${k} is required`);
if (!/^[A-Za-z0-9._-]{1,64}$/.test(args.kid))
  fail('--kid: letters, digits, . _ - only');
if (args.lic.length > 100 || args.sub.length > 200)
  fail('--lic or --sub too long');
if (!['hosted', 'customer'].includes(args.deployment))
  fail('--deployment: hosted or customer');

function day(value, name) {
  const t = /^\d{4}-\d{2}-\d{2}$/.test(value)
    ? Date.parse(`${value}T00:00:00Z`)
    : NaN;
  if (Number.isNaN(t)) fail(`--${name}: expected YYYY-MM-DD`);
  return t / 1000;
}
function amount(value, name) {
  if (value === 'unlimited') return null;
  if (!/^\d{1,9}$/.test(value))
    fail(`--${name}: a whole number or "unlimited"`);
  return Number(value);
}

const iat = Math.floor(Date.now() / 1000);
const nbf = args['not-before'] ? day(args['not-before'], 'not-before') : iat;
const exp = day(args.expires, 'expires');
if (exp <= nbf) fail('--expires must be after the start date');

const payload = {
  v: 1,
  lic: args.lic,
  sub: args.sub,
  deployment: args.deployment,
  iat,
  nbf,
  exp,
  limits: {
    agents: amount(args.agents, 'agents'),
    tenants: amount(args.tenants, 'tenants'),
  },
  features: args.features
    ? args.features
        .split(',')
        .map((f) => f.trim())
        .filter(Boolean)
    : [],
};

let key;
try {
  key = createPrivateKey(readFileSync(args.key === '-' ? 0 : args.key, 'utf8'));
} catch {
  fail('could not read the private key (an unencrypted PKCS#8 PEM)');
}
if (key.asymmetricKeyType !== 'ed25519') fail('the key is not Ed25519');

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const input = `${b64({ alg: 'EdDSA', kid: args.kid, typ: 'JWT' })}.${b64(payload)}`;
const signature = sign(null, Buffer.from(input), key);
if (!verify(null, Buffer.from(input), createPublicKey(key), signature))
  fail('self-check failed');
process.stdout.write(`${input}.${signature.toString('base64url')}\n`);
