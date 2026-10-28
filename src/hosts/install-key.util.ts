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

/**
 * Whether `ip` is inside one of `cidrs` (IPv4 or IPv6). An empty list
 * allows any address; malformed input never allows.
 */
export function ipAllowed(ip: string, cidrs: string[]): boolean {
  if (cidrs.length === 0) return true;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  const address = mapped ? mapped[1]! : ip;
  const family = isIP(address);
  if (family === 0) return false;
  const list = new BlockList();
  for (const cidr of cidrs) {
    const [net, bits] = cidr.split('/');
    const netFamily = isIP(net ?? '');
    const prefix = Number(bits);
    if (
      netFamily === 0 ||
      !Number.isInteger(prefix) ||
      prefix < 0 ||
      prefix > (netFamily === 4 ? 32 : 128)
    ) {
      continue; // a malformed entry matches nothing
    }
    list.addSubnet(net!, prefix, netFamily === 4 ? 'ipv4' : 'ipv6');
  }
  return list.check(address, family === 4 ? 'ipv4' : 'ipv6');
}
