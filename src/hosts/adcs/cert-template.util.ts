import type * as x509 from '@peculiar/x509';

const OID_CERT_TEMPLATE = '1.3.6.1.4.1.311.21.7';

/**
 * The AD CS certificate template OID (szOID_CERTIFICATE_TEMPLATE,
 * `SEQUENCE { templateID OID, majorVersion?, minorVersion? }`), or null when
 * the certificate carries none or it cannot be read.
 */
export function templateOidOf(cert: x509.X509Certificate): string | null {
  const ext = cert.extensions.find((e) => e.type === OID_CERT_TEMPLATE);
  if (!ext) return null;
  const der = new Uint8Array(ext.value);
  if (der[0] !== 0x30) return null;
  let at = 1;
  let len = der[at++]!;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 2) return null;
    len = 0;
    for (let i = 0; i < n; i += 1) len = len * 256 + (der[at++] ?? 0);
  }
  if (der[at] !== 0x06) return null;
  at += 1;
  const oidLen = der[at++]!;
  if (oidLen === 0 || oidLen & 0x80 || at + oidLen > der.length) return null;
  const bytes = der.subarray(at, at + oidLen);
  const first = bytes[0]!;
  const parts: number[] = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (const b of bytes.subarray(1)) {
    value = value * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}
