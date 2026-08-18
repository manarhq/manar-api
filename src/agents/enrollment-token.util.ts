import { createHash, randomBytes } from 'node:crypto';

/**
 * Enrollment tokens are single-use, high-entropy (256 bits of
 * `crypto.randomBytes`) random values, not human-chosen secrets — unlike
 * password hashing, there is no offline-guessability concern a slow KDF
 * (bcrypt/scrypt/argon2) would defend against, since brute-forcing 256 bits
 * of true randomness is infeasible regardless of hash speed. A fast
 * cryptographic hash (SHA-256) is the right tool here, the same reasoning
 * API-key/webhook-secret schemes (Stripe, GitHub, ...) use for hashing
 * bearer tokens at rest.
 *
 * Format: `<tenantSlug>.<base64url secret>`. `POST /agents/enroll` is
 * deliberately unauthenticated (Section 14 -- an agent has no JWT/issuer to
 * carry tenant identity the way a human's token does, per
 * docs/human-auth.md), yet still needs to resolve which tenant's isolated
 * database to look the token up in before it can even attempt a hash
 * lookup. Rather than adding a second configuration knob to the SDK's
 * `enroll(token)` call (the design spec's documented single-argument
 * shape) or trusting a client-supplied tenant slug for anything
 * security-sensitive, the tenant slug rides along as a plaintext,
 * self-describing prefix of the token itself -- not a secret (tenant
 * slugs are not confidential), and bound into the hash along with the
 * rest of the token, so tampering with the prefix after the fact
 * invalidates the hash lookup too. Tenant slugs must not contain "." for
 * this to round-trip; `CreateAgentRequestSchema`'s sibling slug pattern
 * (lowercase alphanumeric + hyphens) already excludes it, and tenant
 * slugs follow the same DNS-label-like convention (see
 * `pnpm manar tenant:create`).
 */

/** Returns a tenant-prefixed, 256-bit random token -- this is the ONLY time the raw value ever exists. */
export function generateEnrollmentToken(tenantSlug: string): string {
  return `${tenantSlug}.${randomBytes(32).toString('base64url')}`;
}

/** `AgentEnrollmentToken.tokenHash` is this value (of the whole raw token, prefix included), never the raw token. */
export function hashEnrollmentToken(rawToken: string): string {
  return createHash('sha256').update(rawToken, 'utf8').digest('hex');
}

/**
 * Extracts the tenant slug prefix from a raw enrollment token, without
 * trusting it for anything beyond "which tenant database do I look this
 * token's hash up in" -- the hash lookup itself (against that tenant's own
 * `AgentEnrollmentToken` table) is what actually authenticates the
 * request. Returns `null` for a malformed token (no `.` separator, or an
 * empty slug/secret half) rather than throwing, so callers can fail closed
 * with a uniform 401.
 */
export function parseEnrollmentTokenTenantSlug(
  rawToken: string,
): string | null {
  const separatorIndex = rawToken.indexOf('.');
  if (separatorIndex <= 0 || separatorIndex === rawToken.length - 1) {
    return null;
  }
  return rawToken.slice(0, separatorIndex);
}
