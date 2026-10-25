import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';

/**
 * Signed offline licence (docs/licensing.md): a compact JWS, alg EdDSA (Ed25519), verified against
 * the public keys shipped in `keys/<kid>.pub`. Pure functions only; nothing here throws on a bad
 * licence and nothing here blocks anything. The licence is a soft limit: it only changes the
 * reported status.
 */

export const LICENSE_STATUSES = [
  'valid',
  'expiring',
  'expired',
  'over_limit',
  'not_yet_valid',
  'invalid_signature',
  'unverifiable',
  'missing',
] as const;
export type LicenseStatusName = (typeof LICENSE_STATUSES)[number];

export const LICENSE_RESOURCES = ['agents', 'tenants'] as const;
export type LicenseResource = (typeof LICENSE_RESOURCES)[number];

/** A licence within this many days of its expiry reports `expiring`. */
export const EXPIRING_WINDOW_DAYS = 30;
/** Clock skew allowed on `nbf`: air-gapped clocks drift. */
const NBF_LEEWAY_SECONDS = 300;
const DAY = 86_400;

export const KID = /^[A-Za-z0-9._-]{1,64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const limit = z.number().int().min(0).nullable();

export const LicensePayloadSchema = z.object({
  v: z.literal(1),
  lic: z.string().min(1).max(100),
  sub: z.string().min(1).max(200),
  deployment: z.enum(['hosted', 'customer']),
  iat: z.number().int(),
  nbf: z.number().int(),
  exp: z.number().int(),
  limits: z.object({ agents: limit, tenants: limit }),
  features: z.array(z.string().min(1).max(64)).max(100),
});
export type LicensePayload = z.infer<typeof LicensePayloadSchema>;

const HeaderSchema = z.object({
  alg: z.literal('EdDSA'),
  kid: z.string().regex(KID),
});

export type Verification =
  | { result: 'missing' }
  | { result: 'malformed' }
  /** `payload` is decoded but NOT trusted: shown by the CLI, never used for limits. */
  | { result: 'unknown_kid'; kid: string; payload: LicensePayload }
  | { result: 'bad_signature'; kid: string; payload: LicensePayload }
  | { result: 'verified'; kid: string; payload: LicensePayload };

function decodeJson(part: string): unknown {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

/** Checks the JWS shape, the trust anchor and the signature. Time and limits are `evaluate`'s. */
export function verifyLicense(
  token: string | undefined,
  keys: ReadonlyMap<string, KeyObject>,
): Verification {
  const jws = token?.trim();
  if (!jws) return { result: 'missing' };
  const parts = jws.split('.');
  if (parts.length !== 3 || !parts.every((p) => B64URL.test(p)))
    return { result: 'malformed' };
  const [h, p, s] = parts as [string, string, string];
  let kid: string;
  let payload: LicensePayload;
  try {
    const header = HeaderSchema.safeParse(decodeJson(h));
    const body = LicensePayloadSchema.safeParse(decodeJson(p));
    if (!header.success || !body.success) return { result: 'malformed' };
    kid = header.data.kid;
    payload = body.data;
  } catch {
    return { result: 'malformed' };
  }
  const key = keys.get(kid);
  if (!key) return { result: 'unknown_kid', kid, payload };
  let ok = false;
  try {
    ok = verify(
      null,
      Buffer.from(`${h}.${p}`),
      key,
      Buffer.from(s, 'base64url'),
    );
  } catch {
    ok = false;
  }
  return { result: ok ? 'verified' : 'bad_signature', kid, payload };
}

export type Usage = Record<LicenseResource, number | null>;

export interface LicenseStatus {
  status: LicenseStatusName;
  /** Why, in a fixed code: malformed, bad_signature, unknown_kid, file_unreadable; else null. */
  reason: string | null;
  deployment: 'hosted' | 'customer';
  kid: string | null;
  /** Claims below come from a verified licence only; null otherwise. */
  licenseId: string | null;
  customer: string | null;
  issuedAt: string | null;
  notBefore: string | null;
  expiresAt: string | null;
  /** Whole days until expiry; negative once expired. */
  daysLeft: number | null;
  limits: Usage | null;
  features: string[];
  usage: Usage;
  /** Resources whose usage is above the licensed amount. */
  overLimit: LicenseResource[];
  checkedAt: string;
}

const iso = (seconds: number) => new Date(seconds * 1000).toISOString();

/** The status for one verification at `now`, given current usage. */
export function evaluate(
  v: Verification,
  usage: Usage,
  now: Date,
  fallbackDeployment: 'hosted' | 'customer',
): LicenseStatus {
  const base: LicenseStatus = {
    status: 'missing',
    reason: null,
    deployment: fallbackDeployment,
    kid: 'kid' in v ? v.kid : null,
    licenseId: null,
    customer: null,
    issuedAt: null,
    notBefore: null,
    expiresAt: null,
    daysLeft: null,
    limits: null,
    features: [],
    usage,
    overLimit: [],
    checkedAt: now.toISOString(),
  };
  switch (v.result) {
    case 'missing':
      return base;
    case 'malformed':
    case 'bad_signature':
      return { ...base, status: 'invalid_signature', reason: v.result };
    case 'unknown_kid':
      return { ...base, status: 'unverifiable', reason: v.result };
  }
  const c = v.payload;
  const nowSec = Math.floor(now.getTime() / 1000);
  const overLimit = LICENSE_RESOURCES.filter((r) => {
    const max = c.limits[r];
    const used = usage[r];
    return max !== null && used !== null && used > max;
  });
  const status: LicenseStatusName =
    c.nbf > nowSec + NBF_LEEWAY_SECONDS
      ? 'not_yet_valid'
      : c.exp <= nowSec
        ? 'expired'
        : overLimit.length > 0
          ? 'over_limit'
          : c.exp - nowSec <= EXPIRING_WINDOW_DAYS * DAY
            ? 'expiring'
            : 'valid';
  return {
    ...base,
    status,
    deployment: c.deployment,
    licenseId: c.lic,
    customer: c.sub,
    issuedAt: iso(c.iat),
    notBefore: iso(c.nbf),
    expiresAt: iso(c.exp),
    daysLeft: Math.floor((c.exp - nowSec) / DAY),
    limits: { agents: c.limits.agents, tenants: c.limits.tenants },
    features: c.features,
    overLimit,
  };
}

/**
 * The trust anchors: every `<kid>.pub` (Ed25519 SPKI PEM) in `dir`. A file that is not an Ed25519
 * public key is skipped and named in `skipped`; a missing directory means no anchors.
 */
export function loadTrustAnchors(dir: string): {
  keys: Map<string, KeyObject>;
  skipped: string[];
} {
  const keys = new Map<string, KeyObject>();
  const skipped: string[] = [];
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith('.pub'));
  } catch {
    return { keys, skipped };
  }
  for (const file of files) {
    const kid = file.slice(0, -'.pub'.length);
    try {
      const key = createPublicKey(readFileSync(join(dir, file), 'utf8'));
      if (!KID.test(kid) || key.asymmetricKeyType !== 'ed25519')
        throw new Error('not an Ed25519 public key');
      keys.set(kid, key);
    } catch {
      skipped.push(file);
    }
  }
  return { keys, skipped };
}

/** Shipped trust anchors: `src/licensing/keys` in dev and tests, `dist/licensing/keys` in the image. */
export const TRUST_ANCHOR_DIR = join(__dirname, 'keys');
