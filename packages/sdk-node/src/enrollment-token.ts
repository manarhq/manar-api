/**
 * Mirrors `manar-api`'s `src/agents/enrollment-token.util.ts` token format
 * (`<tenantSlug>:<agentSlug>:<secret>`) and
 * `src/agents/agent-identifier.ts`'s `buildAgentIdentifier` — see that
 * file's doc comment for the full rationale (in short: the SDK has to
 * build a CSR whose Subject Alternative Name already matches what the
 * server expects *before* making any network call, and `enroll(token)`'s
 * documented single-argument shape means the token itself is the only
 * place that identity information can come from). This is intentionally
 * duplicated rather than imported from `manar-api`'s source — this
 * package has no dependency on the server application, only on the wire
 * format it and the server both agree on.
 */

export interface EnrollmentTokenParts {
  tenantSlug: string;
  agentSlug: string;
}

export function parseEnrollmentTokenParts(
  rawToken: string,
): EnrollmentTokenParts | null {
  const segments = rawToken.split(':');
  if (segments.length !== 3) return null;
  const [tenantSlug, agentSlug, secret] = segments;
  if (!tenantSlug || !agentSlug || !secret) return null;
  return { tenantSlug, agentSlug };
}

export function buildAgentIdentifier(
  tenantSlug: string,
  agentSlug: string,
): string {
  return `agent://${tenantSlug}/${agentSlug}`;
}
