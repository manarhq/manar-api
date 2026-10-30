import { isIP } from 'node:net';
import { z } from 'zod';

/**
 * The reverse proxies in front of the HTTP app (cloudflared and Traefik in the hosted install).
 * With them listed, Fastify's `trustProxy` takes `request.ip` from the `X-Forwarded-For` chain
 * those proxies set, so per-address limits (the public MCP endpoint) see the real caller instead
 * of the proxy pod. Unset: `request.ip` is the TCP peer. Never list a range callers can come from
 * directly: anything in it may set `X-Forwarded-For`.
 */
export const TrustedProxyConfigSchema = z.object({
  MANAR_TRUSTED_PROXY_CIDRS: z
    .string()
    .optional()
    .refine(
      (value) =>
        value === undefined || value === 'none' || parseCidrs(value) !== null,
      'comma-separated IP addresses or CIDR ranges, or none',
    ),
});

/**
 * Per-address limits (the public MCP endpoint, the public `/i/<code>` install scripts) key on
 * `request.ip`. Unset, that is the proxy pod, so every caller shares one bucket and the first
 * 20 requests a minute lock everyone else out. In production the proxies must therefore be named
 * (or `none` for an API exposed directly), whatever else is enabled.
 */
export function trustedProxyIssues(config: {
  MANAR_TRUSTED_PROXY_CIDRS?: string;
  MANAR_MCP_ENABLED?: string;
  NODE_ENV?: string;
}): string[] {
  return (config.NODE_ENV === 'production' ||
    config.MANAR_MCP_ENABLED === 'true') &&
    !config.MANAR_TRUSTED_PROXY_CIDRS?.trim()
    ? [
        'MANAR_TRUSTED_PROXY_CIDRS: required in production and when MANAR_MCP_ENABLED is true (the cloudflared and Traefik pod ranges, or "none" when the API is exposed directly): public routes limit callers per address',
      ]
    : [];
}

/** `a.b.c.d`, `a.b.c.d/n`, IPv6 likewise; null when any entry is not one. */
export function parseCidrs(value: string): string[] | null {
  const entries = value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  for (const entry of entries) {
    const [address, prefix, extra] = entry.split('/');
    const family = isIP(address ?? '');
    if (!family || extra !== undefined) return null;
    if (prefix !== undefined) {
      const bits = Number(prefix);
      if (!/^\d+$/.test(prefix) || bits > (family === 4 ? 32 : 128))
        return null;
    }
  }
  return entries;
}

/** Options for the HTTP app's `FastifyAdapter` (main.ts and the e2e suites that need them). */
export function httpAdapterOptions(env: {
  MANAR_TRUSTED_PROXY_CIDRS?: string;
}): { trustProxy?: string[] } {
  const value = env.MANAR_TRUSTED_PROXY_CIDRS ?? '';
  const cidrs = value.trim() === 'none' ? [] : (parseCidrs(value) ?? []);
  return cidrs.length ? { trustProxy: cidrs } : {};
}

/**
 * The caller's address for address-based controls (install-key ranges, approval-rule ranges).
 * Only trusted when the proxies in front are named (or `none`): unset, `request.ip` may be the
 * proxy pod, so it is reported as `unknown`, which no range matches (fail closed).
 */
export function callerAddress(
  ip: string,
  env: { MANAR_TRUSTED_PROXY_CIDRS?: string },
): string {
  return env.MANAR_TRUSTED_PROXY_CIDRS?.trim() ? ip : 'unknown';
}
