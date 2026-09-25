/**
 * What `CredentialBrokerService` returns in place of a tool result's `data`
 * when the shared DLP classification (`src/common/dlp/dlp-classification.ts`)
 * finds a credential in it (the deterministic floor's credential shapes or a
 * manar-ai credential-type finding), or manar-ai generic PII it could not
 * pin to a string leaf. The whole result is withheld because a
 * secret anywhere in it means the rest cannot be trusted to be clean either.
 *
 * UAE PII and located manar-ai PII are not handled here: they are replaced in
 * place and the rest of the result is returned. E-mail addresses pass through. Finding types and counts
 * (never values) go to the `dlp.result_redacted` audit event.
 */
export function redactedToolResultPlaceholder(
  findingTypes: string[],
  findingCount: number,
): unknown {
  return {
    redacted: true,
    reason: 'sensitive_data_detected',
    findingCount,
    findingTypes: [...new Set(findingTypes)],
  };
}
