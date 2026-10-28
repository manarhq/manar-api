import { createHash, randomBytes } from 'node:crypto';
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

export function hashInstallKey(raw: string): string {
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
