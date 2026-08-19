import { z } from 'zod';

/**
 * Phase 12a (SSRF protection). `SSRF_ALLOWED_HOSTS`: an explicit,
 * operator-controlled exception list to `assertSafeOutboundUrl`'s default
 * "reject private/loopback/link-local/metadata-service addresses" policy —
 * comma-separated exact hostnames (matched against `new URL(...).hostname`,
 * never a range/wildcard), empty by default.
 *
 * This exists for a genuine, unavoidable tension rather than as a general
 * escape hatch: this product's entire purpose is integrating with a
 * tenant's *own* on-prem/internal SIEM/EDR/IAM tools (`docs/tool-gateway.md`),
 * which legitimately live on private network addresses — a blanket,
 * unconditional rejection of all of RFC 1918 space would make the Tool
 * Gateway's real purpose impossible, not just "safer." Loopback and the
 * link-local/metadata range (169.254.0.0/16 — 169.254.169.254 specifically)
 * are never legitimate targets under any circumstance and are NEVER
 * exemptable through this list (see `assertSafeOutboundUrl`'s own
 * enforcement — this allowlist only ever widens which *hostnames* skip the
 * DNS-resolution-based range check entirely, it never widens which IP
 * ranges are considered safe in general). A real production deployment
 * should leave this unset (or scoped to only the specific internal
 * hostnames it genuinely needs to reach) — this repo's own `.env.example`
 * populates it with `127.0.0.1`/`localhost` purely so this phase's own
 * local HTTP test fixtures (which necessarily bind to loopback) and
 * Phase 7a's demo tool container keep working, mirroring how a real
 * deployment would list its own known-internal tool hostnames.
 */
export const SsrfConfigSchema = z.object({
  SSRF_ALLOWED_HOSTS: z.string().default(''),
});

export type SsrfConfig = z.infer<typeof SsrfConfigSchema>;

/** Parses the raw comma-separated config string into a `Set` for `assertSafeOutboundUrl`'s `allowedHosts` option. */
export function parseSsrfAllowedHosts(raw: string): Set<string> {
  return new Set(
    raw
      .split(',')
      .map((host) => host.trim())
      .filter(Boolean),
  );
}
