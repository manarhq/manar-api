import type { DlpAdvisory } from '../../ai-advisory/ai-advisory-client.service';

/**
 * The one DLP classification in manar-api (ADR-0002 "Result DLP"). Both
 * content checkpoints use it, in the same order, so they cannot disagree:
 * the LLM proxy (prompt going out) and `CredentialBrokerService` (tool
 * result coming back to the agent).
 *
 *   1. `applyDlpFloor` (deterministic, in-process, runs whether or not
 *      manar-ai answers):
 *      - credential shapes (JWT, bearer token, PEM private key, Azure
 *        connection string / SAS signature, JSON secret values, Entra client
 *        secret) -> `credentialTypes`; the caller blocks the prompt or
 *        withholds the whole tool result.
 *      - UAE PII (Emirates ID, UAE IBAN, payment card, UAE mobile) ->
 *        replaced in place with `[REDACTED:<TYPE>]`; the rest is kept.
 *      - E-mail addresses / UPNs are not matched: they pass through (the
 *        agent needs them to act; the data stays in the customer's model).
 *   2. manar-ai `AnalyzeDlp` on `dlpScanText(floor.value)`, then
 *      `advisoryBlocks`: only credential finding types block/withhold.
 *      E-mail, other PII and `source: "system"` markers do not.
 *
 * Patterns favour recall on credential shapes (a false positive costs one
 * blocked call; a false negative ships a secret to a model provider).
 */

const CREDENTIAL_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ['jwt', /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}/g],
  ['bearer_token', /\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*/gi],
  ['private_key', /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g],
  [
    'azure_connection_string',
    /\b(?:AccountKey|SharedAccessKey|SharedAccessSignature)\s*=\s*[A-Za-z0-9+/%]{16,}/gi,
  ],
  ['azure_sas_token', /(?:^|[?&\s"'])sig=[A-Za-z0-9%+/]{16,}/g],
  [
    'json_secret_value',
    /"(?:client_?secret|clientSecret|password|passwd|secret)"\s*:\s*"[^"\s]{4,}"/gi,
  ],
  // Entra ID client secret values: 3 chars, a digit, "Q~", then 31-34 chars.
  [
    'entra_client_secret',
    /(?:^|[^A-Za-z0-9_~.-])[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}(?![A-Za-z0-9_~.-])/g,
  ],
];

/** Luhn check on the digits of `match` (separators ignored). */
function luhnValid(match: string): boolean {
  const digits = match.replace(/\D/g, '');
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Applied in order; earlier replacements contain no digits, so later patterns cannot re-match them. */
const PII_PATTERNS: ReadonlyArray<
  readonly [string, RegExp, ((match: string) => boolean)?]
> = [
  // Emirates ID: 784-YYYY-NNNNNNN-C, dashes optional.
  ['emirates_id', /\b784[- ]?\d{4}[- ]?\d{7}[- ]?\d\b/g],
  // UAE IBAN: AE + 2 check digits + 19 digits (3 bank + 16 account), optional grouping spaces.
  ['uae_iban', /\bAE\d{2}(?: ?\d){19}\b/gi],
  // Payment card: 13-19 digits starting 2-6 (Visa/MC/Amex/Discover ranges; keeps epoch-ms
  // timestamps out), optional space/dash grouping, Luhn-valid.
  ['payment_card', /\b[2-6]\d(?:[ -]?\d){11,17}\b/g, luhnValid],
  // UAE mobile: +971 / 00971 / 0, then 50/52/54/55/56/58 and 7 digits.
  [
    'uae_mobile',
    /(?<![\d+])(?:\+971|00971|0)[ -]?5[024568][ -]?\d{3}[ -]?\d{4}(?!\d)/g,
  ],
];

/**
 * Nesting deeper than this is not inspected; it counts as a credential-class
 * finding (`scan_depth_exceeded`), so the caller blocks/withholds. Real
 * Graph/Defender payloads and chat requests are far shallower.
 */
const MAX_DEPTH = 64;

export interface DlpFloorResult<T> {
  /** The input with UAE PII replaced by `[REDACTED:<TYPE>]`. */
  value: T;
  /** Credential pattern names found; non-empty means block / withhold. */
  credentialTypes: string[];
  /** PII pattern names redacted in place. */
  piiTypes: string[];
  /** Match count per finding type (never the values). */
  counts: Record<string, number>;
}

/** Walks every string in `value` (object keys excluded), returning a redacted copy and what was found. */
export function applyDlpFloor<T>(value: T): DlpFloorResult<T> {
  const counts: Record<string, number> = {};
  const credentials = new Set<string>();
  const pii = new Set<string>();
  const hit = (set: Set<string>, name: string, n = 1) => {
    set.add(name);
    counts[name] = (counts[name] ?? 0) + n;
  };

  const scanString = (text: string): string => {
    for (const [name, pattern] of CREDENTIAL_PATTERNS) {
      const n = text.match(pattern)?.length ?? 0;
      if (n > 0) hit(credentials, name, n);
    }
    let out = text;
    for (const [name, pattern, accept] of PII_PATTERNS) {
      out = out.replace(pattern, (match) => {
        if (accept && !accept(match)) return match;
        hit(pii, name);
        return `[REDACTED:${name.toUpperCase()}]`;
      });
    }
    return out;
  };

  const walk = (node: unknown, depth: number): unknown => {
    if (depth > MAX_DEPTH) {
      hit(credentials, 'scan_depth_exceeded');
      return null;
    }
    if (typeof node === 'string') return scanString(node);
    if (Array.isArray(node)) return node.map((n) => walk(n, depth + 1));
    if (node !== null && typeof node === 'object') {
      return Object.fromEntries(
        Object.entries(node).map(([k, v]) => [k, walk(v, depth + 1)]),
      );
    }
    return node;
  };

  const redacted = walk(value, 0) as T;
  return {
    value: redacted,
    credentialTypes: [...credentials].sort(),
    piiTypes: [...pii].sort(),
    counts,
  };
}

/** manar-ai finding types that block a prompt / withhold a tool result. Everything else (e-mail, PII, other) passes. */
const BLOCKING_ADVISORY_TYPES = new Set([
  'TYPE_API_KEY',
  'TYPE_PRIVATE_KEY',
  'TYPE_JWT',
  'TYPE_CREDENTIAL',
]);

/** The blocking manar-ai findings: credential types only, never the `source: "system"` marker (S7). */
export function blockingAdvisoryFindings(
  advisory: DlpAdvisory,
): DlpAdvisory['findings'] {
  return advisory.findings.filter(
    (f) => f.source !== 'system' && BLOCKING_ADVISORY_TYPES.has(f.type),
  );
}

export function advisoryBlocks(advisory: DlpAdvisory): boolean {
  return blockingAdvisoryFindings(advisory).length > 0;
}

/** Every string leaf of `value`, newline-joined: what manar-ai's DLP scan is given on both paths. */
export function dlpScanText(value: unknown): string {
  const parts: string[] = [];
  const walk = (node: unknown): void => {
    if (typeof node === 'string') parts.push(node);
    else if (Array.isArray(node)) node.forEach(walk);
    else if (node !== null && typeof node === 'object')
      Object.values(node).forEach(walk);
  };
  walk(value);
  return parts.join('\n');
}
