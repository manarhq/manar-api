import { BlockList, isIP } from 'node:net';

/** The pod ranges DESK calls from (STAFF_TRUSTED_PROXY_CIDRS); empty trusts nobody. */
export function trustedPeers(cidrs: string | undefined): BlockList {
  const list = new BlockList();
  for (const entry of (cidrs ?? '')
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean)) {
    const [address, prefix] = entry.split('/');
    const family = isIP(address ?? '') === 6 ? 'ipv6' : 'ipv4';
    if (!isIP(address ?? '')) continue;
    if (prefix === undefined) list.addAddress(address!, family);
    else list.addSubnet(address!, Number(prefix), family);
  }
  return list;
}

const unmap = (ip: string) =>
  ip.startsWith('::ffff:') && isIP(ip.slice(7)) === 4 ? ip.slice(7) : ip;

/**
 * The staff member's address for the audit chain. DESK forwards it in `x-manar-client-ip`; that
 * header counts only when the TCP peer is a DESK pod and it holds exactly one IP address. Anything
 * else is ignored and the peer stands in. Both are recorded.
 */
export function clientIpOf(
  peer: string | undefined,
  header: unknown,
  trusted: BlockList,
): { clientIp?: string; peerIp?: string } {
  const peerIp = peer ? unmap(peer) : undefined;
  const value = typeof header === 'string' ? header.trim() : '';
  const fromDesk =
    !!peerIp &&
    !!isIP(peerIp) &&
    trusted.check(peerIp, isIP(peerIp) === 6 ? 'ipv6' : 'ipv4');
  return { clientIp: fromDesk && isIP(value) ? unmap(value) : peerIp, peerIp };
}
