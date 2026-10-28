import * as x509 from '@peculiar/x509';

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

const CRL_TIMEOUT_MS = 5_000;
const CRL_MAX_BYTES = 5 * 1024 * 1024;

/** One bounded fetch: no redirects, 5 s, 5 MB. Throws on any problem. */
export async function fetchCrlHttp(url: string): Promise<Uint8Array> {
  const response = await fetch(url, {
    redirect: 'error',
    signal: AbortSignal.timeout(CRL_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`CRL fetch status ${response.status}`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > CRL_MAX_BYTES) throw new Error('CRL too large');
  return bytes;
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
  fetchCrl: (url: string) => Promise<Uint8Array> = fetchCrlHttp,
  now: Date = new Date(),
): Promise<Revocation> {
  for (const url of crlUrls(leaf)) {
    try {
      const crl = new x509.X509Crl(await fetchCrl(url));
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
