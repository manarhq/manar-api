import type {
  DlpAdvisory,
  DlpFindingAdvisory,
} from '../../ai-advisory/ai-advisory-client.service';

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
 *      E-mail and `source: "system"` markers do not.
 *   3. manar-ai generic findings (`TYPE_PII`, `TYPE_OTHER`) are redacted in
 *      place at string-leaf granularity (`classifyDlp`): manar-ai reports
 *      only a type and a model-written preview, no offsets, so the leaf that
 *      carries the finding is located by re-scanning halves of the leaf set
 *      and replaced whole with `[REDACTED:PII]` / `[REDACTED:OTHER]`.
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

/** manar-ai finding types that block a prompt / withhold a tool result. Generic PII/other is redacted in place (`classifyDlp`); e-mail passes. */
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
  return stringLeaves(value).join('\n');
}

/** manar-ai finding types redacted in place (whole string leaf). E-mail is deliberately absent: UPNs pass. */
const GENERIC_ADVISORY_TYPES = new Set(['TYPE_PII', 'TYPE_OTHER']);

/**
 * Upper bound on the extra `AnalyzeDlp` calls spent locating generic
 * findings in one prompt / tool result. Bisection needs about
 * 2 x log2(leaves) calls per flagged leaf, so 32 locates a few flagged
 * leaves among thousands. Past the bound the content is blocked / withheld,
 * never passed.
 */
export const DLP_LOCATE_MAX_CALLS = 32;

export interface DlpClassification<T> {
  /** Floor-redacted input with every leaf manar-ai flagged as generic PII replaced by `[REDACTED:PII|OTHER]`. */
  value: T;
  /** Floor credential pattern names (block / withhold). */
  credentialTypes: string[];
  /** Floor PII pattern names redacted in place. */
  piiTypes: string[];
  /** Floor match count per pattern name (never values). */
  counts: Record<string, number>;
  /** manar-ai's answer on the whole text; `undefined` when not asked (a floor credential already blocks), `null` when unavailable. */
  advisory: DlpAdvisory | null | undefined;
  /** Non-`system` manar-ai credential findings, from the whole text or any located part of it. */
  blockingFindings: DlpFindingAdvisory[];
  /** String leaves replaced per manar-ai generic type, e.g. `{ TYPE_PII: 2 }` (never values). */
  advisoryRedactedCounts: Record<string, number>;
  /** Generic types manar-ai reported that could not be pinned to a leaf (call bound hit, a call returned null, or no part reproduced the finding). Non-empty blocks / withholds. */
  unlocatedTypes: string[];
  /** True when the caller must block the prompt / withhold the whole result. */
  blocked: boolean;
}

const genericTypes = (advisory: DlpAdvisory): string[] => [
  ...new Set(
    advisory.findings
      .filter(
        (f) => f.source !== 'system' && GENERIC_ADVISORY_TYPES.has(f.type),
      )
      .map((f) => f.type),
  ),
];

/**
 * The full classification both checkpoints run: floor, manar-ai on the
 * floor's string leaves, then in-place redaction of generic findings.
 * `analyze` is the caller's `AnalyzeDlp` (the proxy's throws fail closed;
 * a `null` on the whole text is returned for the caller to decide: the proxy
 * blocks, the result path skips manar-ai).
 */
export async function classifyDlp<T>(
  input: T,
  analyze: (content: string) => Promise<DlpAdvisory | null>,
): Promise<DlpClassification<T>> {
  const floor = applyDlpFloor(input);
  const result: DlpClassification<T> = {
    ...floor,
    advisory: undefined,
    blockingFindings: [],
    advisoryRedactedCounts: {},
    unlocatedTypes: [],
    blocked: floor.credentialTypes.length > 0,
  };
  if (result.blocked) return result;

  const advisory = await analyze(dlpScanText(floor.value));
  result.advisory = advisory;
  if (advisory === null) return result;
  result.blockingFindings = blockingAdvisoryFindings(advisory);
  const rootTypes = genericTypes(advisory);
  if (result.blockingFindings.length > 0 || rootTypes.length === 0) {
    result.blocked = result.blockingFindings.length > 0;
    return result;
  }

  // Locate the flagged leaves by bisection over the distinct string leaves.
  const leaves = [...new Set(stringLeaves(floor.value).filter((s) => s))];
  const flagged = new Map<string, string>();
  const unlocated = new Set<string>();
  let calls = 0;
  const locate = async (group: string[], types: string[]): Promise<boolean> => {
    if (types.length === 0) return false;
    if (group.length === 0) {
      types.forEach((t) => unlocated.add(t));
      return true;
    }
    if (group.length === 1) {
      flagged.set(
        group[0]!,
        types.includes('TYPE_PII') ? 'TYPE_PII' : types[0]!,
      );
      return true;
    }
    const halves = [
      group.slice(0, group.length >> 1),
      group.slice(group.length >> 1),
    ];
    if (calls + 2 > DLP_LOCATE_MAX_CALLS) {
      types.forEach((t) => unlocated.add(t));
      return true;
    }
    calls += 2;
    const answers = await Promise.all(halves.map((h) => analyze(h.join('\n'))));
    if (answers.some((a) => a === null)) {
      types.forEach((t) => unlocated.add(t));
      return true;
    }
    const found = await Promise.all(
      answers.map((a, i) => {
        result.blockingFindings.push(...blockingAdvisoryFindings(a!));
        return locate(halves[i]!, genericTypes(a!));
      }),
    );
    // The group was flagged but neither half reproduces it: the finding
    // depends on context the leaves do not carry alone. Not locatable.
    if (!found.some(Boolean)) types.forEach((t) => unlocated.add(t));
    return true;
  };
  await locate(leaves, rootTypes);

  result.unlocatedTypes = [...unlocated].sort();
  result.blocked =
    result.blockingFindings.length > 0 || result.unlocatedTypes.length > 0;
  if (result.blocked) return result;

  const replace = (node: unknown): unknown => {
    if (typeof node === 'string') {
      const type = flagged.get(node);
      if (!type) return node;
      result.advisoryRedactedCounts[type] =
        (result.advisoryRedactedCounts[type] ?? 0) + 1;
      return `[REDACTED:${type.replace(/^TYPE_/, '')}]`;
    }
    if (Array.isArray(node)) return node.map(replace);
    if (node !== null && typeof node === 'object') {
      return Object.fromEntries(
        Object.entries(node).map(([k, v]) => [k, replace(v)]),
      );
    }
    return node;
  };
  result.value = replace(floor.value) as T;
  return result;
}

function stringLeaves(value: unknown): string[] {
  const parts: string[] = [];
  const walk = (node: unknown): void => {
    if (typeof node === 'string') parts.push(node);
    else if (Array.isArray(node)) node.forEach(walk);
    else if (node !== null && typeof node === 'object')
      Object.values(node).forEach(walk);
  };
  walk(value);
  return parts;
}
