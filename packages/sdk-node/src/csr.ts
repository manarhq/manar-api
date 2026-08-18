import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(webcrypto as unknown as Crypto);

/**
 * ECDSA P-256 — matches `CertificateAuthorityService`'s expectations and
 * current guidance for new X.509 workload-identity PKI (NIST accommodates
 * P-256/P-384; P-256 gives RSA-3072-equivalent strength at a fraction of
 * the key/signature size, which matters here since every enrollment and
 * mTLS handshake pays this cost). See docs/agent-identity.md.
 */
const KEY_ALGORITHM = {
  name: 'ECDSA',
  namedCurve: 'P-256',
  hash: 'SHA-256',
} as const;

export interface GeneratedCsr {
  /** PEM-encoded PKCS#10 certificate request, ready to POST to /agents/enroll. */
  csrPem: string;
  /** PEM-encoded (PKCS#8) private key. This is the ONLY place it ever exists outside encrypted storage — never transmitted, never logged. */
  privateKeyPem: string;
}

/**
 * Generates a fresh ECDSA P-256 keypair locally and builds a CSR whose
 * Subject Alternative Name is exactly `identifier`
 * (`agent://<tenantSlug>/<slug>`) — the string
 * `CertificateAuthorityService` requires to match the enrolling agent's
 * expected identity before it will sign anything. The private key never
 * leaves this function except as the returned PEM, which the caller
 * (`ManarAgent.enroll`) hands directly to `IdentityStore.save` — it is
 * never included in the CSR itself (only the public key is) and never
 * sent over the network.
 */
export async function generateAgentCsr(
  identifier: string,
): Promise<GeneratedCsr> {
  // Node's `node:crypto` webcrypto types and the DOM lib's `CryptoKeyPair`
  // (what @peculiar/x509's public API is typed against) differ only in a
  // handful of newer KeyUsage string literals neither this codebase nor
  // @peculiar/x509 uses — the same cast `certificate-authority.service.ts`
  // needs for `cryptoProvider.set()`.
  const keys = (await webcrypto.subtle.generateKey(KEY_ALGORITHM, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;

  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: `CN=${identifier}`,
    keys,
    signingAlgorithm: KEY_ALGORITHM,
    extensions: [
      new x509.SubjectAlternativeNameExtension([
        new x509.GeneralName('url', identifier),
      ]),
    ],
  });

  const privateKeyPkcs8 = await webcrypto.subtle.exportKey(
    'pkcs8',
    keys.privateKey,
  );
  const privateKeyPem = x509.PemConverter.encode(
    privateKeyPkcs8,
    x509.PemConverter.PrivateKeyTag,
  );

  return { csrPem: csr.toString('pem'), privateKeyPem };
}
