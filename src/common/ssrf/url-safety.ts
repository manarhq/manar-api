import { promises as dns } from 'node:dns';
import { isIPv4, isIPv6 } from 'node:net';

/**
 * Phase 12a (SSRF protection). Thrown by `assertSafeOutboundUrl` — every
 * call site catches this and turns it into whatever failure shape its own
 * layer already uses (a `ToolInvocationResult.success: false` for the tool
 * adapters, a `BadRequestException` for webhook registration, a delivery
 * failure for webhook dispatch) rather than letting it propagate as a raw
 * unhandled error.
 */
export class UnsafeOutboundUrlError extends Error {
  constructor(
    public readonly url: string,
    public readonly reasonCode: string,
  ) {
    super(`Outbound URL "${url}" was rejected: ${reasonCode}`);
    this.name = 'UnsafeOutboundUrlError';
  }
}

/** A single resolved address, the shape `dns.lookup(host, { all: true })` returns — narrowed here so a test's fake resolver only needs to produce this much. */
export interface ResolvedAddress {
  address: string;
  family: number;
}

/** Injectable for testing (see `url-safety.spec.ts`'s DNS-rebinding scenario, which passes a fake resolver that returns a different address on each call) — defaults to a real DNS lookup in production. */
export type DnsLookupFn = (hostname: string) => Promise<ResolvedAddress[]>;

const defaultLookup: DnsLookupFn = (hostname) =>
  dns.lookup(hostname, { all: true, verbatim: true });

/**
 * IPv4 ranges rejected: loopback (127.0.0.0/8), "this network" (0.0.0.0/8),
 * RFC 1918 private space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
 * link-local (169.254.0.0/16 — this is also the block the AWS/Azure/GCP
 * instance metadata service lives in, 169.254.169.254 specifically),
 * carrier-grade NAT (100.64.0.0/10), IETF protocol assignments/benchmarking
 * (192.0.0.0/24, 198.18.0.0/15), and multicast/reserved (224.0.0.0/4 and
 * above).
 */
function isPrivateOrReservedIpv4(address: string): boolean {
  const octets = address.split('.').map((part) => Number(part));
  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n))) return true; // malformed -- fail closed
  const a = octets[0] as number;
  const b = octets[1] as number;

  if (a === 0) return true;
  if (a === 127) return true;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true; // multicast (224-239) + reserved (240-255)
  return false;
}

/**
 * IPv6 ranges rejected: loopback (::1), unspecified (::), link-local
 * (fe80::/10 — the IPv6 analogue of 169.254.0.0/16), unique-local
 * (fc00::/7, RFC 4193's non-globally-routable space), and any IPv4-mapped
 * address (`::ffff:a.b.c.d`) whose embedded IPv4 address is itself
 * private/reserved per `isPrivateOrReservedIpv4`.
 */
function isPrivateOrReservedIpv6(address: string): boolean {
  const lower = address.toLowerCase();
  if (lower === '::1' || lower === '::') return true;

  const v4Mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (v4Mapped?.[1]) return isPrivateOrReservedIpv4(v4Mapped[1]);

  // fc00::/7 -- first 7 bits are 1111 110x, i.e. the first hex nibble is c-f
  // and covers "fc"/"fd" as the first byte.
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
  // fe80::/10 -- first byte fe, second byte's top 6 bits 10xxxxxx (80-bf).
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;

  return false;
}

/**
 * The one shared, reusable SSRF guard every outbound-URL-accepting surface
 * in this codebase calls — `Tool.baseEndpoint` (`HttpToolAdapter`/
 * `McpToolAdapter`, retrofitted this phase) and `WebhookEndpoint.url`
 * (registration AND delivery, both new this phase). Never duplicated
 * per-caller logic (see docs/security.md's SSRF section).
 *
 * Two things happen, in order:
 *   1. Only `http:`/`https:` are accepted at all — no `file:`, `ftp:`,
 *      `gopher:`, `data:`, etc.
 *   2. The hostname is actually resolved (an IP literal resolves to itself
 *      instantly via `dns.lookup`, so this one code path covers both
 *      "someone registered a raw private IP" and "someone registered a
 *      hostname that resolves to one") and *every* returned address is
 *      checked against the private/loopback/link-local/metadata-service
 *      ranges above — a single bad address among several is enough to
 *      reject the whole URL (fail closed).
 *
 * **Deliberately never cached, and callers must call this at the actual
 * moment of use, not just once at registration** — a hostname that
 * resolved to a public address when a `Tool`/`WebhookEndpoint` was first
 * registered can be repointed (DNS rebinding) to resolve to an internal
 * address by the time a real request is made. This function does a fresh
 * lookup on every call for exactly that reason; it has no internal cache
 * for a caller to accidentally rely on stale results from.
 */
export async function assertSafeOutboundUrl(
  rawUrl: string,
  lookup: DnsLookupFn = defaultLookup,
): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new UnsafeOutboundUrlError(rawUrl, 'not_a_valid_url');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new UnsafeOutboundUrlError(rawUrl, 'protocol_not_allowed');
  }

  // Strip surrounding brackets from an IPv6 literal host (`new URL(...)`
  // includes them in `.hostname`, e.g. `[::1]`) -- `dns.lookup` and the
  // IPv6 range checks above both expect the bare address form.
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');

  let addresses: ResolvedAddress[];
  try {
    addresses = await lookup(hostname);
  } catch (error) {
    throw new UnsafeOutboundUrlError(
      rawUrl,
      `hostname_unresolvable:${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (addresses.length === 0) {
    throw new UnsafeOutboundUrlError(
      rawUrl,
      'hostname_resolved_to_no_addresses',
    );
  }

  for (const { address } of addresses) {
    const unsafe = isIPv4(address)
      ? isPrivateOrReservedIpv4(address)
      : isIPv6(address)
        ? isPrivateOrReservedIpv6(address)
        : true; // neither -- fail closed, this should never happen from a real dns.lookup
    if (unsafe) {
      throw new UnsafeOutboundUrlError(
        rawUrl,
        `resolves_to_private_or_reserved_address:${address}`,
      );
    }
  }
}
