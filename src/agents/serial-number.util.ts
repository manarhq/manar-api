/**
 * Certificate serial numbers show up in three different textual shapes in
 * this codebase, and every one of them must agree for revocation to
 * actually take effect:
 *
 *   - OpenBao's `sign-verbatim`/`revoke` API: colon-separated hex
 *     (`39:DD:2E:...`).
 *   - `@peculiar/x509`'s `X509Certificate.serialNumber` getter (used both
 *     to parse the cert OpenBao just issued, and to parse an mTLS peer
 *     certificate in `AgentMtlsGuard`): hex, no separators.
 *   - `AgentCertificate.serialNumber` (this codebase's storage format):
 *     normalized to uppercase hex, no separators — so a value obtained via
 *     either of the above paths compares equal after normalization,
 *     without caring which path produced it.
 */

/** Canonical storage/comparison form: uppercase hex, no separators. */
export function normalizeSerialNumber(serial: string): string {
  return serial.replace(/:/g, '').toUpperCase();
}

/** OpenBao's own colon-separated hex form, for calls to its revoke endpoint. */
export function toColonSeparatedHex(serial: string): string {
  const normalized = normalizeSerialNumber(serial);
  const pairs = normalized.match(/.{1,2}/g);
  if (!pairs) {
    throw new Error(
      `Cannot convert malformed serial number "${serial}" to colon-hex`,
    );
  }
  return pairs.join(':');
}
