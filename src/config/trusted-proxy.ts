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
      (value) => value === undefined || parseCidrs(value) !== null,
      'comma-separated IP addresses or CIDR ranges',
    ),
});

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
  const cidrs = parseCidrs(env.MANAR_TRUSTED_PROXY_CIDRS ?? '') ?? [];
  return cidrs.length ? { trustProxy: cidrs } : {};
}
