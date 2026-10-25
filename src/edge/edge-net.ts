import { ICANN_SUFFIX_RULES, PRIVATE_SUFFIX_RULES } from './public-suffix-list';

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

/** Special-use and non-public names (RFC 6761, 6762, 7686, 9476 and `.internal`): never reachable through the proxy. */
const RESERVED_TLDS = new Set([
  'local',
  'internal',
  'localhost',
  'onion',
  'arpa',
  'test',
  'invalid',
  'alt',
]);

interface SuffixRules {
  exact: Set<string>;
  wild: Set<string>;
  except: Set<string>;
}

function parseRules(text: string): SuffixRules {
  const rules: SuffixRules = {
    exact: new Set(),
    wild: new Set(),
    except: new Set(),
  };
  for (const rule of text.split('\n')) {
    if (!rule) continue;
    if (rule.startsWith('!')) rules.except.add(rule.slice(1));
    else if (rule.startsWith('*.')) rules.wild.add(rule.slice(2));
    else rules.exact.add(rule);
  }
  return rules;
}

let icann: SuffixRules | undefined;
let privateRules: SuffixRules | undefined;

function matches(rules: SuffixRules, name: string): boolean {
  if (rules.except.has(name)) return false;
  if (rules.exact.has(name)) return true;
  const dot = name.indexOf('.');
  return dot > 0 && rules.wild.has(name.slice(dot + 1));
}

/** True when `name` is a public suffix (Public Suffix List, ICANN and private sections). */
export function isPublicSuffix(name: string): boolean {
  icann ??= parseRules(ICANN_SUFFIX_RULES);
  privateRules ??= parseRules(PRIVATE_SUFFIX_RULES);
  return matches(icann, name) || matches(privateRules, name);
}

/** True when the top-level label is a delegated ICANN TLD (`com`, `uk`, `ae`, ...). */
export function isIcannTld(tld: string): boolean {
  icann ??= parseRules(ICANN_SUFFIX_RULES);
  return icann.exact.has(tld) || icann.wild.has(tld);
}

/**
 * Normalizes an allow-list host (trim, lowercase) and returns it, or null when it is not a DNS
 * name or `*.` + a DNS name: no IPs, ports, paths or other wildcards, at most 253 characters, at
 * least two labels after any `*.`, a top-level label that is not all digits (so an IPv4 literal
 * never passes), a TLD the ICANN section of the Public Suffix List delegates (so internal names
 * like `.svc`, `.lan`, `.corp`, `.home` never pass) and not a special-use name (`.local`,
 * `.internal`, `.localhost`, `.onion`, `.arpa`, ...). A wildcard must not cover a whole public
 * suffix (`*.co.uk`, `*.github.io`).
 */
export function normalizeEgressHost(input: string): string | null {
  const host = input.trim().toLowerCase();
  if (host.length === 0 || host.length > 253) return null;
  const wildcard = host.startsWith('*.');
  const name = wildcard ? host.slice(2) : host;
  const labels = name.split('.');
  if (labels.length < 2) return null;
  if (!labels.every((label) => LABEL.test(label))) return null;
  const tld = labels[labels.length - 1] ?? '';
  if (RESERVED_TLDS.has(tld) || !isIcannTld(tld)) return null;
  if (wildcard && isPublicSuffix(name)) return null;
  return host;
}
