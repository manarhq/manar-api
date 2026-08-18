/**
 * An agent's SPIFFE-like workload identity URI: `agent://<tenantSlug>/<slug>`.
 * This is the exact string `CertificateAuthorityService` requires an
 * enrollment CSR's Subject Alternative Name (URI type) to match before it
 * will ever ask OpenBao to sign anything (the actual security boundary —
 * see that service), and the same string `AgentMtlsGuard` resolves an
 * mTLS request's verified client certificate by.
 */
export function buildAgentIdentifier(
  tenantSlug: string,
  agentSlug: string,
): string {
  return `agent://${tenantSlug}/${agentSlug}`;
}

const AGENT_IDENTIFIER_PATTERN = /^agent:\/\/([^/]+)\/([^/]+)$/;

export interface ParsedAgentIdentifier {
  tenantSlug: string;
  agentSlug: string;
}

/**
 * Parses an `agent://<tenantSlug>/<slug>` identifier back into its parts —
 * used by `AgentMtlsGuard` to resolve which tenant database to look the
 * agent up in from a verified client certificate's SAN alone (there is no
 * JWT/issuer on the mTLS surface to carry tenant identity). Returns `null`
 * for anything that doesn't match the exact expected shape — never throws,
 * so callers can fail closed with their own 401 rather than leak a parse
 * error's detail.
 */
export function parseAgentIdentifier(
  identifier: string,
): ParsedAgentIdentifier | null {
  const match = AGENT_IDENTIFIER_PATTERN.exec(identifier);
  if (!match) return null;
  const [, tenantSlug, agentSlug] = match;
  if (!tenantSlug || !agentSlug) return null;
  return { tenantSlug, agentSlug };
}
