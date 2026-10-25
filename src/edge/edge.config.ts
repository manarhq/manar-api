import { z } from 'zod';
import { isWgPublicKey, parseCidr } from './edge-net';

const optionalString = z.preprocess(
  (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
  z.string().optional(),
);

/**
 * Manar edge (docs/edge.md): the WireGuard gateway every governed agent's network path goes
 * through. Off by default. When on, the gateway endpoint, its public key, the sync API token and
 * the agents host name are required; startup stops here otherwise.
 */
export const EdgeConfigSchema = z.object({
  MANAR_EDGE_ENABLED: z.enum(['true', 'false']).default('false'),
  /** Overlay network; the gateway takes the first host. */
  MANAR_EDGE_CIDR: z
    .string()
    .default('100.88.0.0/16')
    .refine((v) => parseCidr(v) !== null, {
      message:
        'MANAR_EDGE_CIDR must be an IPv4 network a.b.c.d/n with n between 8 and 30',
    }),
  /** `<host>:51820`, handed to enrolling hosts. */
  MANAR_EDGE_ENDPOINT: optionalString,
  /** The gateway's WireGuard public key (base64, 32 bytes). */
  MANAR_EDGE_GATEWAY_PUBLIC_KEY: optionalString,
  /** Bearer token of the internal sync API (`/internal/v1/edge/*`). Secret. */
  MANAR_EDGE_GATEWAY_TOKEN: optionalString,
  /** Host name of the agent mTLS listener; hosts set it as SNI through the tunnel. */
  MANAR_AGENTS_HOST: optionalString,
});

export type EdgeConfig = z.infer<typeof EdgeConfigSchema>;

/** Cross-field rules, merged into the app schema's `superRefine` (env.validation.ts). */
export function edgeConfigIssues(c: EdgeConfig): string[] {
  if (c.MANAR_EDGE_ENABLED !== 'true') return [];
  const issues: string[] = [];
  if (
    !c.MANAR_EDGE_ENDPOINT ||
    !/^[^\s:/]+:[0-9]{1,5}$/.test(c.MANAR_EDGE_ENDPOINT)
  )
    issues.push(
      'MANAR_EDGE_ENDPOINT must be <host>:<port> when MANAR_EDGE_ENABLED=true',
    );
  if (
    !c.MANAR_EDGE_GATEWAY_PUBLIC_KEY ||
    !isWgPublicKey(c.MANAR_EDGE_GATEWAY_PUBLIC_KEY)
  )
    issues.push(
      'MANAR_EDGE_GATEWAY_PUBLIC_KEY must be a base64 WireGuard public key when MANAR_EDGE_ENABLED=true',
    );
  if (!c.MANAR_EDGE_GATEWAY_TOKEN || c.MANAR_EDGE_GATEWAY_TOKEN.length < 32)
    issues.push(
      'MANAR_EDGE_GATEWAY_TOKEN must be at least 32 characters when MANAR_EDGE_ENABLED=true',
    );
  if (!c.MANAR_AGENTS_HOST || !/^[a-z0-9.-]+$/i.test(c.MANAR_AGENTS_HOST))
    issues.push(
      'MANAR_AGENTS_HOST must be a host name when MANAR_EDGE_ENABLED=true',
    );
  return issues;
}
