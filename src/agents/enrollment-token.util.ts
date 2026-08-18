import { createHash, randomBytes } from 'node:crypto';

/**
 * Enrollment tokens are single-use, high-entropy (256 bits of
 * `crypto.randomBytes`) random values, not human-chosen secrets -- unlike
 * password hashing, there is no offline-guessability concern a slow KDF
 * (bcrypt/scrypt/argon2) would defend against, since brute-forcing 256 bits
 * of true randomness is infeasible regardless of hash speed. A fast
 * cryptographic hash (SHA-256) is the right tool here, the same reasoning
 * API-key/webhook-secret schemes (Stripe, GitHub, ...) use for hashing
 * bearer tokens at rest.
 *
 * Format: `<tenantSlug>:<agentSlug>:<base64url secret>`. Two problems
 * neither the design spec nor a bare random token solve on their own:
 *
 *   1. `POST /agents/enroll` is deliberately unauthenticated (Section 14
 *      -- an agent has no JWT/issuer to carry tenant identity the way a
 *      human's token does, per docs/human-auth.md), yet still needs to
 *      resolve which tenant's isolated database to look the token up in
 *      before it can even attempt a hash lookup.
 *   2. The SDK's `enroll(token)` (packages/sdk-node) builds its CSR's
 *      Subject Alternative Name *before* talking to the server at all --
 *      it has to already know the exact `agent://<tenantSlug>/<slug>`
 *      identifier `CertificateAuthorityService` will check the CSR
 *      against, but the design spec's documented call shape is a single
 *      `token` argument, with no separate identifier parameter.
 *
 * Both are solved by having the tenant slug *and* the agent slug ride
 * along as a plaintext, self-describing prefix of the token itself --
 * neither is a secret (slugs are not confidential; only the trailing
 * random segment is), and the whole raw token (prefix included) is what
 * gets hashed, so tampering with either slug after the fact invalidates
 * the hash lookup too. Slugs must not contain ":" for this to round-trip;
 * `CreateAgentRequestSchema`'s slug pattern (lowercase alphanumeric +
 * hyphens) already excludes it, and tenant slugs follow the same
 * DNS-label-like convention (see `pnpm manar tenant:create`). `:` was
 * chosen over `.`/`/` specifically because it never appears in
 * base64url's alphabet either, so the three segments can never be
 * ambiguously split.
 */

export interface EnrollmentTokenParts {
  tenantSlug: string;
  agentSlug: string;
}

/** Returns a tenant/agent-prefixed, 256-bit random token -- this is the ONLY time the raw value ever exists. */
export function generateEnrollmentToken(parts: EnrollmentTokenParts): string {
  return `${parts.tenantSlug}:${parts.agentSlug}:${randomBytes(32).toString('base64url')}`;
}

/** `AgentEnrollmentToken.tokenHash` is this value (of the whole raw token, prefix included), never the raw token. */
export function hashEnrollmentToken(rawToken: string): string {
  return createHash('sha256').update(rawToken, 'utf8').digest('hex');
}

/**
 * Extracts the tenant/agent slug prefix from a raw enrollment token,
 * without trusting it for anything beyond "which tenant database do I
 * look this token's hash up in, and what identifier should the CSR
 * claim" -- the hash lookup itself (against that tenant's own
 * `AgentEnrollmentToken` table, and `CertificateAuthorityService`'s SAN
 * check against the *stored* `Agent.identifier`) is what actually
 * authenticates the request and enforces identity. Returns `null` for a
 * malformed token (wrong segment count, or any empty segment) rather than
 * throwing, so callers can fail closed with a uniform 401.
 */
export function parseEnrollmentTokenParts(
  rawToken: string,
): EnrollmentTokenParts | null {
  const segments = rawToken.split(':');
  if (segments.length !== 3) return null;
  const [tenantSlug, agentSlug, secret] = segments;
  if (!tenantSlug || !agentSlug || !secret) return null;
  return { tenantSlug, agentSlug };
}
