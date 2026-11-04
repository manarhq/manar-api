import { isIP } from 'node:net';

/** AC-39: first character of the local part, then the domain: `m•••@fixio.ae`. */
export function maskEmail(email: string | null | undefined): string | null {
  if (!email) return null;
  const at = email.lastIndexOf('@');
  if (at <= 0) return '•••';
  return `${email[0]}•••${email.slice(at)}`;
}

/** `/24` for IPv4, `/48` for IPv6 (spec §12). */
export function maskIp(ip: string | null | undefined): string | null {
  if (!ip) return null;
  const family = isIP(ip);
  if (family === 4) return `${ip.split('.').slice(0, 3).join('.')}.0/24`;
  if (family === 6) {
    const head = ip.split('::')[0]!.split(':').filter(Boolean);
    return `${[...head, '0', '0', '0']
      .slice(0, 3)
      .join(':')
      .replace(/(:0)+$/, '')}::/48`;
  }
  return null;
}

/** Last four characters only (IdP ids, Stripe ids on a revealed record). */
export const lastFour = (v: string | null | undefined) =>
  v ? `…${v.slice(-4)}` : null;
