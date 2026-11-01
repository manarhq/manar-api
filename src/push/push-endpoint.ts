/**
 * Push endpoints are URLs the API will POST to, so a subscriber must not be able to aim them at
 * anything else (SSRF). Only the browsers' own push services are accepted: https, port 443, a DNS
 * name (never an IP literal) under one of the allowed suffixes. Checked when subscribing and again
 * before every send.
 */
const ALLOWED_HOSTS = [
  'fcm.googleapis.com',
  'web.push.apple.com',
  'updates.push.services.mozilla.com',
];
const ALLOWED_SUFFIXES = [
  '.push.services.mozilla.com',
  '.notify.windows.com',
  '.push.apple.com',
];

export function isAllowedPushEndpoint(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol !== 'https:' || u.username || u.password) return false;
  if (u.port !== '' && u.port !== '443') return false;
  const host = u.hostname.toLowerCase();
  // IP literals: IPv6 brackets, or a dotted-quad / numeric host.
  if (host.startsWith('[') || /^[0-9.]+$/.test(host) || !host.includes('.'))
    return false;
  return (
    ALLOWED_HOSTS.includes(host) ||
    ALLOWED_SUFFIXES.some((s) => host.endsWith(s) && host.length > s.length)
  );
}
