import { createHash, createHmac, randomBytes } from 'node:crypto';
import { BlockList, isIP } from 'node:net';

/**
 * Install keys (docs/hosts.md): `mik_<tenantSlug>_<43 base64url chars>`.
 * The tenant slug in the prefix decides the tenant, so a host never picks
 * its own tenant; the key itself is 256 random bits, stored only as SHA-256.
 */
const KEY = /^mik_([a-z0-9][a-z0-9-]*)_([A-Za-z0-9_-]{43})$/;

/** The only time the raw value exists. */
export function generateInstallKey(tenantSlug: string): string {
  return `mik_${tenantSlug}_${randomBytes(32).toString('base64url')}`;
}

/**
 * How a key (or an "Add device" short code) is stored: HMAC-SHA256 under the server secret
 * `MANAR_INSTALL_KEY_HMAC_SECRET`, so a copy of the database cannot be used to test guesses of a
 * 49-bit short code offline. Unset (dev, tests, or before the secret is delivered) it is plain
 * SHA-256, the format keys had before.
 */
export function hashInstallKey(raw: string): string {
  const secret = process.env.MANAR_INSTALL_KEY_HMAC_SECRET;
  return secret
    ? createHmac('sha256', secret).update(raw, 'utf8').digest('hex')
    : legacyHashInstallKey(raw);
}

/** Keys created before the secret existed are stored as plain SHA-256 and still resolve. */
export function legacyHashInstallKey(raw: string): string {
  return createHash('sha256').update(raw, 'utf8').digest('hex');
}

export function tenantSlugOf(raw: string): string | null {
  return KEY.exec(raw)?.[1] ?? null;
}

/** `network/prefix` with exactly one `/` and a decimal prefix in range; nothing looser. */
function parseCidr(
  cidr: string,
): { net: string; prefix: number; family: 'ipv4' | 'ipv6' } | null {
  const m = /^([^/\s]+)\/(\d{1,3})$/.exec(cidr);
  if (!m) return null;
  const family = isIP(m[1]!);
  const prefix = Number(m[2]);
  if (family === 0 || prefix > (family === 4 ? 32 : 128)) return null;
  return { net: m[1]!, prefix, family: family === 4 ? 'ipv4' : 'ipv6' };
}

export function isValidCidr(cidr: string): boolean {
  return parseCidr(cidr) !== null;
}

/**
 * Whether `ip` is inside one of `cidrs` (IPv4 or IPv6). An empty list
 * allows any address; malformed input never allows (a malformed entry
 * matches nothing; writers reject them up front with `isValidCidr`).
 */
export function ipAllowed(ip: string, cidrs: string[]): boolean {
  if (cidrs.length === 0) return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  const address = mapped ? mapped[1]! : ip;
  const family = isIP(address);
  if (family === 0) return false;
  const list = new BlockList();
  for (const cidr of cidrs) {
    const parsed = parseCidr(cidr);
    if (parsed) list.addSubnet(parsed.net, parsed.prefix, parsed.family);
  }
  return list.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

/** An install key's lifetime or uses are outside what a workspace may choose. */
export class InstallKeyLimitError extends Error {}

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

/**
 * Lifetime and uses of a new install key (founder decision, 4 Nov 2026): 24 hours and one use by
 * default; an admin picks 1 hour to 30 days and up to 10,000 uses. Up to 365 days only when the
 * key is locked to address ranges (IT packages deploy over months). There is no "never expires".
 * ponytail: the Entra lock (A2) is not built, so only an address-range lock allows the long key.
 */
export function installKeyLimits(
  input: { expiresAt?: Date; maxUses?: number; allowedCidrs?: string[] },
  now: Date = new Date(),
): { expiresAt: Date; maxUses: number } {
  const expiresAt = input.expiresAt ?? new Date(now.getTime() + DAY_MS);
  const ms = expiresAt.getTime() - now.getTime();
  const locked = (input.allowedCidrs ?? []).length > 0;
  const max = (locked ? 365 : 30) * DAY_MS;
  if (!(ms >= HOUR_MS && ms <= max)) {
    throw new InstallKeyLimitError(
      locked
        ? 'An install key must expire between 1 hour and 365 days from now.'
        : 'An install key must expire between 1 hour and 30 days from now. Lock it to address ranges to allow up to 365 days.',
    );
  }
  const maxUses = input.maxUses ?? 1;
  if (!(Number.isInteger(maxUses) && maxUses >= 1 && maxUses <= 10_000)) {
    throw new InstallKeyLimitError(
      'An install key may be used 1 to 10,000 times.',
    );
  }
  return { expiresAt, maxUses };
}
