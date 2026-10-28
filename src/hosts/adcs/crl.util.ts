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

/**
 * Revocation status of `leaf` from its CRL distribution points. The CRL must
 * be signed by `issuer`, name it, and not be past `nextUpdate`. `unknown`
 * (no HTTP point, unreachable, unparseable, badly signed, stale) is never
 * treated as good by callers.
 */
export async function checkRevocation(
  leaf: x509.X509Certificate,
  issuer: x509.X509Certificate,
  fetchCrl: (url: string) => Promise<Uint8Array> = (url) => fetchCrlHttp(url),
  now: Date = new Date(),
): Promise<Revocation> {
  for (const url of crlUrls(leaf)) {
    try {
      const crl = new x509.X509Crl(new Uint8Array(await fetchCrl(url)));
      if (crl.issuer !== issuer.subject) continue;
      if (!(await crl.verify({ publicKey: issuer.publicKey }))) continue;
      if (!crl.nextUpdate || crl.nextUpdate < now || crl.thisUpdate > now)
        continue;
      return crl.findRevoked(leaf) ? 'revoked' : 'good';
    } catch {
      continue;
    }
  }
  return 'unknown';
}
