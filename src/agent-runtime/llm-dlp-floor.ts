/**
 * Deterministic, in-process DLP floor for the LLM proxy (ADR-0002, Gate 0
 * S6/S29). It runs before manar-ai is asked anything and does not depend on
 * it: a credential shape blocks the call, UAE PII is replaced with a
 * placeholder before the prompt leaves manar-api. manar-ai's answer can only
 * add restriction on top of this.
 *
 * Patterns favour recall on credential shapes (a false positive costs one
 * blocked LLM call; a false negative ships a secret to a model provider).
 */

const CREDENTIAL_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ['jwt', /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/],
  ['bearer_token', /\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*/i],
  ['private_key', /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/],
  [
    'azure_connection_string',
    /\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)\s*=\s*[A-Za-z0-9+/%]{16,}/i,
  ],
  ['azure_sas_token', /(?:^|[?&\s"'])sig=[A-Za-z0-9%+/]{16,}/],
  [
    'json_secret_value',
    /"(?:client_?secret|clientSecret|password|passwd|secret)"\s*:\s*"[^"\s]{4,}"/i,
  ],
  // Entra ID client secret values: 3 chars, a digit, "Q~", then 31-34 chars.
  [
    'entra_client_secret',
    /(?:^|[^A-Za-z0-9_~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.-])/,
  ],
];

const PII_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  // Emirates ID: 784-YYYY-NNNNNNN-C, dashes optional.
  ['emirates_id', /\b784[- ]?\d{4}[- ]?\d{7}[- ]?\d\b/g],
  // UAE IBAN: AE + 2 check digits + 19 digits (3 bank + 16 account), optional grouping spaces.
  ['uae_iban', /\bAE\d{2}(?: ?\d){19}\b/gi],
];

export interface DlpFloorResult<T> {
  /** The input with UAE PII replaced by `[REDACTED:<type>]`. */
  value: T;
  /** Credential pattern names found; non-empty means the call must be blocked. */
  credentialTypes: string[];
  /** PII pattern names redacted. */
  piiTypes: string[];
}

function scanString(
  text: string,
  credentials: Set<string>,
  pii: Set<string>,
): string {
  for (const [name, pattern] of CREDENTIAL_PATTERNS) {
    if (pattern.test(text)) credentials.add(name);
  }
  let out = text;
  for (const [name, pattern] of PII_PATTERNS) {
    out = out.replace(pattern, () => {
      pii.add(name);
      return `[REDACTED:${name.toUpperCase()}]`;
    });
  }
  return out;
}

/** Walks every string in `value` (object keys excluded), returning a redacted copy and what was found. */
export function applyDlpFloor<T>(value: T): DlpFloorResult<T> {
  const credentials = new Set<string>();
  const pii = new Set<string>();
  const walk = (node: unknown): unknown => {
    if (typeof node === 'string') return scanString(node, credentials, pii);
    if (Array.isArray(node)) return node.map(walk);
    if (node !== null && typeof node === 'object') {
      return Object.fromEntries(
        Object.entries(node).map(([k, v]) => [k, walk(v)]),
      );
    }
    return node;
  };
  const redacted = walk(value) as T;
  return {
    value: redacted,
    credentialTypes: [...credentials].sort(),
    piiTypes: [...pii].sort(),
  };
}
