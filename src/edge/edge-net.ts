/**
 * Pure helpers for the Manar edge (docs/edge.md): overlay addressing, WireGuard key shape and the
 * egress allow-list host syntax. No I/O; the config schema and the services both use them.
 */

export interface Cidr {
  /** Network address as an unsigned 32-bit integer. */
  network: number;
  prefix: number;
}

function ipToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255) return null;
    value = value * 256 + Number(part);
  }
  return value;
}

export function intToIp(value: number): string {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join('.');
}

/** `a.b.c.d/n` with the host bits zero and room for the gateway plus at least one peer (n <= 30). */
export function parseCidr(cidr: string): Cidr | null {
  const [ip, bits, extra] = cidr.split('/');
  if (extra !== undefined || !bits || !/^[0-9]{1,2}$/.test(bits)) return null;
  const prefix = Number(bits);
  const network = ipToInt(ip ?? '');
  if (network === null || prefix < 8 || prefix > 30) return null;
  const hostBits = 2 ** (32 - prefix);
  if (network % hostBits !== 0) return null;
  return { network, prefix };
}

/** The gateway's overlay IP: the first host of the CIDR (`100.88.0.1` for the default). */
export function gatewayIp(cidr: Cidr): string {
  return intToIp(cidr.network + 1);
}

/**
 * The lowest free peer address (`a.b.c.d/32`), from the second host up to the last one before
 * broadcast, or null when the range is full. `held` are the addresses rows already hold.
 */
export function nextFreeAddress(
  cidr: Cidr,
  held: ReadonlySet<string>,
): string | null {
  const last = cidr.network + 2 ** (32 - cidr.prefix) - 2;
  // ponytail: linear scan of the range under the global edge lock; fine for a /16 (65k peers).
  for (let host = cidr.network + 2; host <= last; host++) {
    const address = `${intToIp(host)}/32`;
    if (!held.has(address)) return address;
  }
  return null;
}

/** A WireGuard public key: canonical base64 of exactly 32 bytes. */
export function isWgPublicKey(value: string): boolean {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === 32 && bytes.toString('base64') === value;
}

const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Normalizes an allow-list host (trim, lowercase) and returns it, or null when it is not a DNS
 * name or `*.` + a DNS name: no IPs, ports, paths or other wildcards, at most 253 characters, at
 * least two labels after any `*.`, and a top-level label that is not all digits (so an IPv4
 * literal never passes).
 */
export function normalizeEgressHost(input: string): string | null {
  const host = input.trim().toLowerCase();
  if (host.length === 0 || host.length > 253) return null;
  const name = host.startsWith('*.') ? host.slice(2) : host;
  const labels = name.split('.');
  if (labels.length < 2) return null;
  if (!labels.every((label) => LABEL.test(label))) return null;
  if (/^[0-9]+$/.test(labels[labels.length - 1] ?? '')) return null;
  return host;
}
