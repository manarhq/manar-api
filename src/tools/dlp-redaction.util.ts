import type { DlpAdvisory } from '../ai-advisory/ai-advisory-client.service';

/**
 * Placeholder `CredentialBrokerService` substitutes for a tool result's
 * `data` when `AiAdvisoryClient.analyzeDlp` reports one or more findings on
 * that result (see docs/ai-security-model.md's DLP-after-call checkpoint).
 *
 * The gRPC contract deliberately never transmits a finding's raw matched
 * value *or* its offset within the scanned content, even internally within
 * manar-ai (Section 73 — see `manar-ai`'s `DlpFinding.redactedPreview` doc
 * comment) — only a short, already-redacted preview per finding. That
 * means `manar-api` cannot precisely splice out just the matched
 * substring(s) from the original result without re-deriving detection
 * locally (which would duplicate manar-ai's ownership of DLP pattern
 * matching, exactly what Section 73's "never rely solely on an LLM /
 * never re-implement detection in two places" posture argues against).
 * Given that real interface constraint, whole-value redaction — replacing
 * the entire `data` payload with this fixed placeholder — is what actually
 * achieves the security goal (the agent's own context/output channel can
 * never become an exfiltration path for whatever the tool leaked) using
 * only the signal the contract legitimately provides. The full finding
 * metadata (types, count, redacted previews) is preserved separately in
 * the audit trail via `AuditService.recordSafely` — never in what's
 * returned to the agent.
 */
export function redactedToolResultPlaceholder(
  findings: DlpAdvisory['findings'],
): unknown {
  return {
    redacted: true,
    reason: 'sensitive_data_detected',
    findingCount: findings.length,
    findingTypes: [...new Set(findings.map((f) => f.type))],
  };
}
