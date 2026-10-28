import * as x509 from '@peculiar/x509';
import {
  safeOutboundFetch,
  type DnsLookupFn,
} from '../../common/ssrf/url-safety';
import type { SsrfPolicy } from '../../common/ssrf/ssrf.config';

export type Revocation = 'good' | 'revoked' | 'unknown';

/** HTTP(S) CRL distribution points named by the certificate. LDAP points are not used. */
export function crlUrls(cert: x509.X509Certificate): string[] {
  const ext = cert.getExtension(x509.CRLDistributionPointsExtension);
  const urls: string[] = [];
  for (const dp of ext?.distributionPoints ?? []) {
    for (const name of dp.distributionPoint?.fullName ?? []) {
      const uri = name.uniformResourceIdentifier;
      if (uri && /^https?:\/\//i.test(uri)) urls.push(uri);
    }
  }
  return urls;
}

export const CRL_TIMEOUT_MS = 5_000;
export const CRL_MAX_BYTES = 5 * 1024 * 1024;

export interface CrlFetchOptions {
  /** `SSRF_ALLOWED_HOSTS` / loopback policy; a private PKI host must be allow-listed there. */
  policy?: SsrfPolicy;
  fetchImpl?: typeof fetch;
  lookup?: DnsLookupFn;
  timeoutMs?: number;
  maxBytes?: number;
}

/**
 * One bounded fetch through the SSRF guard (the URL comes from a certificate
 * the client presented): http/https only, private ranges refused unless the
 * host is allow-listed, no redirects, a timeout, and the body counted as it
 * streams and cancelled the moment it passes the cap. Throws on any problem.
 */
export async function fetchCrlHttp(
  url: string,
  options: CrlFetchOptions = {},
): Promise<Uint8Array> {
  const maxBytes = options.maxBytes ?? CRL_MAX_BYTES;
  const response = await safeOutboundFetch(url, {
    method: 'GET',
    headers: {},
    maxRedirects: 0,
    signal: AbortSignal.timeout(options.timeoutMs ?? CRL_TIMEOUT_MS),
    fetchImpl: options.fetchImpl,
    lookup: options.lookup,
    allowedHosts: options.policy?.allowedHosts,
    allowLoopback: options.policy?.allowLoopback,
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`CRL fetch status ${response.status}`);
  }
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error('CRL too large');
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw new Error('CRL too large');
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks);
}

const OID_CRL_NUMBER = '2.5.29.20';
const OID_DELTA_INDICATOR = '2.5.29.27';
const OID_FRESHEST_CRL = '2.5.29.46';
const REASON_REMOVE_FROM_CRL = 8;

/** Collects every `[6] uniformResourceIdentifier` in a DER blob (CRLDistributionPoints / FreshestCRL). */
function derUris(der: Uint8Array): string[] {
  const out: string[] = [];
  const walk = (buf: Uint8Array) => {
    let at = 0;
    while (at + 2 <= buf.length) {
      const tag = buf[at]!;
      let len = buf[at + 1]!;
      let head = 2;
      if (len & 0x80) {
        const n = len & 0x7f;
        if (n === 0 || n > 4 || at + 2 + n > buf.length) return;
        len = 0;
        for (let k = 0; k < n; k += 1) len = len * 256 + buf[at + 2 + k]!;
        head = 2 + n;
      }
      if (at + head + len > buf.length) return;
      const body = buf.subarray(at + head, at + head + len);
      if (tag === 0x86) out.push(Buffer.from(body).toString('ascii'));
      else if (tag & 0x20 || tag === 0x30) walk(body);
      at += head + len;
    }
  };
  walk(der);
  return out.filter((u) => /^https?:\/\//i.test(u));
}

function derInteger(der: Uint8Array): bigint | null {
  if (der[0] !== 0x02 || der.length < 3) return null;
  const len = der[1]!;
  if (len & 0x80 || der.length !== 2 + len) return null;
  return BigInt('0x' + Buffer.from(der.subarray(2)).toString('hex'));
}

const extValue = (
  e: { type: string; value: ArrayBuffer } | undefined,
): Uint8Array | null => (e ? new Uint8Array(e.value) : null);

function freshestUrls(src: x509.X509Certificate | x509.X509Crl): string[] {
  const ext = src.extensions.find((e) => e.type === OID_FRESHEST_CRL);
  const v = extValue(ext);
  return v ? derUris(v) : [];
}

/** A CRL that names `issuer`, is signed by it and is current; otherwise null. */
async function loadCrl(
  url: string,
  issuer: x509.X509Certificate,
  fetchCrl: (url: string) => Promise<Uint8Array>,
  now: Date,
): Promise<x509.X509Crl | null> {
  try {
    const crl = new x509.X509Crl(new Uint8Array(await fetchCrl(url)));
    if (crl.issuer !== issuer.subject) return null;
    if (!(await crl.verify({ publicKey: issuer.publicKey }))) return null;
    if (!crl.nextUpdate || crl.nextUpdate < now || crl.thisUpdate > now) {
      return null;
    }
    return crl;
  } catch {
    return null;
  }
}

/**
 * Revocation status of `leaf` from its CRL distribution points. The CRL must
 * be signed by `issuer`, name it, and not be past `nextUpdate`. When the leaf
 * or the base CRL names a Freshest CRL (AD CS: weekly base, daily delta), a
 * valid delta is required too: same issuer and signature, current, built on
 * a base CRL number no newer than the base we hold. Its entries are added to
 * the base's. `unknown` (no HTTP point, unreachable, unparseable, badly
 * signed, stale, delta not checkable) is never treated as good by callers.
 */
export async function checkRevocation(
  leaf: x509.X509Certificate,
  issuer: x509.X509Certificate,
  fetchCrl: (url: string) => Promise<Uint8Array> = (url) => fetchCrlHttp(url),
  now: Date = new Date(),
): Promise<Revocation> {
  for (const url of crlUrls(leaf)) {
    const base = await loadCrl(url, issuer, fetchCrl, now);
    // A delta is not a complete CRL.
    if (!base || base.extensions.some((e) => e.type === OID_DELTA_INDICATOR)) {
      continue;
    }
    if (base.findRevoked(leaf)) return 'revoked';
    const deltaUrls = [
      ...new Set([...freshestUrls(leaf), ...freshestUrls(base)]),
    ];
    if (deltaUrls.length === 0) return 'good';
    const baseNumber = derInteger(
      extValue(base.extensions.find((e) => e.type === OID_CRL_NUMBER)) ??
        new Uint8Array(),
    );
    if (baseNumber === null) continue;
    for (const durl of deltaUrls) {
      const delta = await loadCrl(durl, issuer, fetchCrl, now);
      if (!delta) continue;
      const indicator = derInteger(
        extValue(
          delta.extensions.find((e) => e.type === OID_DELTA_INDICATOR),
        ) ?? new Uint8Array(),
      );
      if (indicator === null || indicator > baseNumber) continue;
      const hit = delta.findRevoked(leaf);
      if (hit && Number(hit.reason) !== REASON_REMOVE_FROM_CRL)
        return 'revoked';
      return 'good';
    }
  }
  return 'unknown';
}
