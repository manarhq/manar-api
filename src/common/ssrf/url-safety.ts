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

  const embedded = embeddedIpv4(lower);
  if (embedded) return isPrivateOrReservedIpv4(embedded);

  // fc00::/7 -- first 7 bits are 1111 110x, i.e. the first hex nibble is c-f
  // and covers "fc"/"fd" as the first byte.
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
  // fe80::/10 -- first byte fe, second byte's top 6 bits 10xxxxxx (80-bf).
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;

  return false;
}

/**
 * The IPv4 address carried inside an IPv4-mapped (`::ffff:0:0/96`),
 * IPv4-compatible (`::/96`) or NAT64 (`64:ff9b::/96`) IPv6 address, in
 * either the dotted form or the hex form the WHATWG URL parser produces
 * (`new URL('http://[::ffff:127.0.0.1]/').hostname` is `[::ffff:7f00:1]`).
 * Gate 0 finding S1: only the dotted mapped form used to be recognised, so
 * `http://[::ffff:7f00:1]/` reached loopback and `[::ffff:a9fe:a9fe]` the
 * metadata service.
 */
function embeddedIpv4(lowerIpv6: string): string | null {
  const match =
    /^(?:::ffff:|::|64:ff9b::)(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/.exec(
      lowerIpv6,
    );
  if (!match) return null;
  if (match[1]) return match[1];
  const high = parseInt(match[2] as string, 16);
  const low = parseInt(match[3] as string, 16);
  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.');
}

type AddressClass = 'public' | 'private' | 'loopback' | 'never';

/**
 * `private` (RFC 1918, CGNAT, benchmarking, unique-local) may be reached
 * through an allow-listed hostname. `loopback` only with `allowLoopback`
 * as well (local development). `never` (link-local and the metadata
 * service, unspecified, multicast, reserved) is never reachable.
 */
function classifyAddress(address: string): AddressClass {
  let v4: string | null = isIPv4(address) ? address : null;
  if (!v4 && isIPv6(address)) {
    const lower = address.toLowerCase();
    if (lower === '::1') return 'loopback';
    v4 = embeddedIpv4(lower);
    if (!v4) {
      if (/^fe[89ab][0-9a-f]:/.test(lower) || lower === '::') return 'never';
      if (/^f[cd][0-9a-f]{2}:/.test(lower)) return 'private';
      return isPrivateOrReservedIpv6(lower) ? 'never' : 'public';
    }
  }
  if (!v4) return 'never';
  if (!isPrivateOrReservedIpv4(v4)) return 'public';
  const [a, b] = v4.split('.').map(Number) as [number, number];
  if (a === 127) return 'loopback';
  if (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19))
  ) {
    return 'private';
  }
  return 'never';
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
 *
 * `options.allowedHosts` (see `src/common/ssrf/ssrf.config.ts`'s
 * `SSRF_ALLOWED_HOSTS`) is an exact-hostname exception list every caller
 * threads through from config — checked *before* any DNS lookup, so an
 * allow-listed hostname skips the range check entirely regardless of what
 * it resolves to. This is a deliberately narrow, operator-controlled
 * escape hatch for this product's real need to integrate with a tenant's
 * own internal tools (see that config field's doc comment for why), never
 * a general bypass.
 */
export async function assertSafeOutboundUrl(
  rawUrl: string,
  options: {
    lookup?: DnsLookupFn;
    allowedHosts?: ReadonlySet<string>;
    allowLoopback?: boolean;
  } = {},
): Promise<void> {
  const lookup = options.lookup ?? defaultLookup;
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

  // Gate 0 finding S2: the allowlist used to skip resolution and every
  // range check. It now only widens which *classes* of address this host
  // may resolve to, and never to link-local or the metadata service.
  const allowListed = options.allowedHosts?.has(hostname) ?? false;

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
    const addressClass = classifyAddress(address);
    const permitted =
      addressClass === 'public' ||
      (addressClass === 'private' && allowListed) ||
      (addressClass === 'loopback' &&
        allowListed &&
        options.allowLoopback === true);
    if (!permitted) {
      throw new UnsafeOutboundUrlError(
        rawUrl,
        `resolves_to_private_or_reserved_address:${address}`,
      );
    }
  }
}

/**
 * Thrown when an outbound response's body exceeds the caller's byte
 * budget. Separate from `UnsafeOutboundUrlError` because it is not a URL
 * policy decision: the URL was legitimate, the *response* was hostile (or
 * simply enormous). Callers map it to their own failure shape the same way.
 */
export class OutboundResponseTooLargeError extends Error {
  constructor(
    public readonly url: string,
    public readonly maxBytes: number,
  ) {
    super(
      `Outbound response from "${url}" exceeded the ${maxBytes}-byte response limit`,
    );
    this.name = 'OutboundResponseTooLargeError';
  }
}

/**
 * How many redirect hops `safeOutboundFetch` will follow before giving up.
 * Deliberately smaller than a browser's ~20: a legitimate tool or webhook
 * endpoint needs one or two hops at most (http→https, a trailing-slash
 * canonicalisation, a vanity domain), while a long chain is either a loop
 * or an attempt to exhaust something.
 */
export const MAX_OUTBOUND_REDIRECTS = 3;

/** Default body-size budget for `readBoundedResponseText`. Comfortably larger than any real tool response this product consumes, small enough that a malicious endpoint cannot exhaust the process's heap. */
export const MAX_OUTBOUND_RESPONSE_BYTES = 2 * 1024 * 1024;

/** Statuses that carry a `Location` header for the client to follow. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([
  301, 302, 303, 307, 308,
]);

/**
 * Request headers that are *credentials* and must therefore never travel
 * to an origin other than the one the caller chose. `Authorization` is the
 * one that matters here (`HttpToolAdapter` puts a broker-issued tool
 * credential in it), the other two are included because they are
 * credentials by the same definition and cost nothing to cover.
 *
 * Note what is deliberately *not* in this list: `WebhookDeliveryService`'s
 * `Manar-Signature`. That header is not a bearer credential — it is an
 * HMAC over one specific body and timestamp, useless for authenticating
 * anything else, and a receiver that legitimately redirects still needs it
 * to verify the delivery it finally receives. Stripping it would break
 * real deliveries and protect nothing.
 */
const CREDENTIAL_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
  // GitLab's token header (`GitLabToolAdapter`, ADR-0011).
  'private-token',
]);

export interface SafeOutboundFetchOptions {
  method: string;
  headers: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  /** Applied to the first hop only; redirect targets must be public (Gate 0 S2). See `SSRF_ALLOWED_HOSTS`. */
  allowedHosts?: ReadonlySet<string>;
  /** Development only — see `SSRF_ALLOW_LOOPBACK`. */
  allowLoopback?: boolean;
  /** Injectable DNS resolver, for tests — see `DnsLookupFn`. */
  lookup?: DnsLookupFn;
  /** Injectable `fetch`, for tests. Defaults to the global one. */
  fetchImpl?: typeof fetch;
  maxRedirects?: number;
}

/**
 * The one outbound HTTP entry point for URLs a *tenant* supplied
 * (`Tool.baseEndpoint`, `WebhookEndpoint.url`). Callers must use this
 * rather than bare `fetch`, because `assertSafeOutboundUrl` on its own is
 * only half an SSRF control.
 *
 * The hole it closes: `fetch` (undici) defaults to `redirect: 'follow'`,
 * and it follows redirects *inside* the runtime, with no callback and no
 * opportunity for application code to inspect where it is being sent. So a
 * tenant-registered host that passes every check at request time can
 * simply answer `302 Location: http://169.254.169.254/latest/meta-data/`
 * and the process will dutifully fetch the cloud instance metadata
 * service — and, worse, undici replays the original request headers on a
 * same-scheme redirect, so `HttpToolAdapter`'s
 * `Authorization: Bearer <broker-issued credential>` goes with it. That is
 * both an SSRF bypass and a credential exfiltration primitive, reachable by
 * anyone who can register a tool or a webhook endpoint.
 *
 * So redirects are taken away from the runtime (`redirect: 'manual'`) and
 * followed here, explicitly, with three rules:
 *
 *   1. **Every hop is re-validated.** `assertSafeOutboundUrl` runs against
 *      each new URL before it is fetched, exactly as it does for the first
 *      one — a redirect target gets no more trust than a registered one.
 *   2. **Credentials do not cross an origin boundary.** Any hop to a
 *      different scheme/host/port drops `CREDENTIAL_HEADERS`, so the worst
 *      a redirecting endpoint can achieve is making this process issue an
 *      *unauthenticated* request somewhere else.
 *   3. **The chain is bounded** at `MAX_OUTBOUND_REDIRECTS`; exceeding it
 *      is an `UnsafeOutboundUrlError`, the same failure shape every caller
 *      already handles.
 *
 * Method/body rewriting follows the same rules the runtime's own redirect
 * handling (and every browser) applies, so switching to manual following
 * does not change how a legitimate endpoint behaves: 303 always becomes a
 * bodiless `GET`, 301/302 become `GET` for a `POST` (long-standing
 * practice the whole web depends on), and 307/308 preserve method and body
 * by definition.
 *
 * Known, accepted limitation: there is still a TOCTOU gap between
 * `assertSafeOutboundUrl`'s DNS resolution and the connection `fetch`
 * makes with its own separate resolution, so a sufficiently fast DNS
 * rebind can slip an address past the check. Closing it properly needs a
 * custom undici connector that pins the validated address, which is a
 * larger change than this fix; the redirect hole closed here is the
 * *practical* bypass, requiring nothing but an HTTP response.
 */
export async function safeOutboundFetch(
  rawUrl: string,
  options: SafeOutboundFetchOptions,
): Promise<Response> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const maxRedirects = options.maxRedirects ?? MAX_OUTBOUND_REDIRECTS;

  let currentUrl = rawUrl;
  let method = options.method;
  let body = options.body;
  let headers = { ...options.headers };

  for (let hop = 0; ; hop += 1) {
    await assertSafeOutboundUrl(
      currentUrl,
      hop === 0
        ? {
            lookup: options.lookup,
            allowedHosts: options.allowedHosts,
            allowLoopback: options.allowLoopback,
          }
        : { lookup: options.lookup },
    );

    const response = await fetchImpl(currentUrl, {
      method,
      headers,
      body,
      signal: options.signal,
      redirect: 'manual',
    });

    if (!REDIRECT_STATUSES.has(response.status)) {
      return response;
    }

    const location = response.headers.get('location');
    if (!location) {
      // A 3xx with no `Location` is not something to follow — hand it back
      // and let the caller treat it as the non-2xx it is.
      return response;
    }

    if (hop >= maxRedirects) {
      await discardBody(response);
      throw new UnsafeOutboundUrlError(
        currentUrl,
        `too_many_redirects:${maxRedirects}`,
      );
    }

    let next: URL;
    try {
      next = new URL(location, currentUrl);
    } catch {
      await discardBody(response);
      throw new UnsafeOutboundUrlError(
        location,
        'redirect_location_not_a_valid_url',
      );
    }
    await discardBody(response);

    if (next.origin !== new URL(currentUrl).origin) {
      // 307/308 replay the body, which the agent supplied for the original
      // tool. It is not forwarded to another origin (Gate 0 finding S2).
      if (body !== undefined && !shouldRewriteToGet(response.status, method)) {
        throw new UnsafeOutboundUrlError(
          next.toString(),
          'cross_origin_redirect_would_replay_body',
        );
      }
      headers = stripCredentialHeaders(headers);
    }

    if (shouldRewriteToGet(response.status, method)) {
      method = 'GET';
      body = undefined;
      headers = stripBodyHeaders(headers);
    }

    currentUrl = next.toString();
  }
}

/**
 * Reads a response body with a hard byte ceiling, so a hostile endpoint
 * cannot answer a tool call with an unbounded stream and exhaust this
 * process's memory — the failure mode a bare `await response.json()` has.
 * Checks the advertised `Content-Length` first (cheap, and rejects the
 * honest case without transferring anything) but never trusts it: the
 * stream is counted as it arrives and aborted the moment it crosses the
 * budget, whatever the header claimed.
 */
export async function readBoundedResponseText(
  response: Response,
  maxBytes: number = MAX_OUTBOUND_RESPONSE_BYTES,
): Promise<string> {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await discardBody(response);
    throw new OutboundResponseTooLargeError(response.url, maxBytes);
  }

  if (!response.body) return '';

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new OutboundResponseTooLargeError(response.url, maxBytes);
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  chunks.push(decoder.decode());
  return chunks.join('');
}

/**
 * Releases a response whose body this code will never read (a redirect
 * hop, or a response being rejected). Without this the underlying socket
 * stays checked out of undici's pool until the response is garbage
 * collected. Failures are ignored: the body may already be consumed or the
 * connection already gone, and neither is worth failing a request over.
 */
async function discardBody(response: Response): Promise<void> {
  await response.body?.cancel().catch(() => undefined);
}

function stripCredentialHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !CREDENTIAL_HEADERS.has(name.toLowerCase()),
    ),
  );
}

function stripBodyHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const bodyHeaders = new Set(['content-type', 'content-length']);
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !bodyHeaders.has(name.toLowerCase()),
    ),
  );
}

/** 303 is defined as "fetch the other resource with GET"; 301/302 on a POST is the same rewrite every HTTP client has done for decades. 307/308 exist precisely to preserve the method, so they never rewrite. */
function shouldRewriteToGet(status: number, method: string): boolean {
  const upper = method.toUpperCase();
  if (upper === 'GET' || upper === 'HEAD') return false;
  if (status === 303) return true;
  return (status === 301 || status === 302) && upper === 'POST';
}
