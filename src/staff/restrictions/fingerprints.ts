import { createHmac } from 'node:crypto';
import type { StaffFingerprintKind } from '../../generated/control-client/client';

const GMAIL = new Set(['gmail.com', 'googlemail.com']);

/**
 * AC-25: lower case, NFKC, trim; drop a `+tag` for every domain; for Gmail also drop dots and map
 * googlemail.com to gmail.com. Null when the value is not an address.
 */
export function normalizeEmail(raw: string): string | null {
  const v = raw.normalize('NFKC').trim().toLowerCase();
  const at = v.lastIndexOf('@');
  if (at <= 0 || at === v.length - 1) return null;
  let local = v.slice(0, at);
  let domain = v.slice(at + 1);
  const plus = local.indexOf('+');
  if (plus >= 0) local = local.slice(0, plus);
  if (GMAIL.has(domain)) {
    local = local.replaceAll('.', '');
    domain = 'gmail.com';
  }
  return local ? `${local}@${domain}` : null;
}

/** HMAC-SHA256(key, kind + value), hex: a database leak reveals no address, card or device. */
export function fingerprint(
  kind: StaffFingerprintKind,
  value: string,
  key: string,
): string {
  return createHmac('sha256', key)
    .update(`${kind}\u0000${value}`)
    .digest('hex');
}
