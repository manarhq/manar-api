import { isIPv4, isIPv6 } from 'node:net';

/**
 * Commands and paths stored for the Sessions view are redacted the way the device redacts its
 * telemetry samples: a port of manar-edge `internal/telemetry` redactPortable (secrets, URL user
 * and query, IPs, emails, random-looking runs, home folders), cut to 512 characters. The device
 * still sends the real command, because the decision needs it; only this copy is kept.
 * `host-contract.json` (shared with manar-edge) pins both implementations to the same answers.
 */
const MAX_SAMPLE = 512;
const MAX_INPUT = 64 * 1024;
const REDACTED = '<redacted>';

const reURL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>`]+/gi;
const reMask = /\[MANAR-MASKED:[a-z_]+\]/g;
const reJWT = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
const reBearer = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const rePEM =
  /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;
const reAssign =
  /\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|passwd|pwd|api[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_.-]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s"',;&]+)/gi;
const reFlag =
  /(--?(?:[a-z0-9-]*(?:secret|token|passw(?:or)?d|pass|pwd|api-?key|credential)[a-z0-9-]*)[ =]+)("[^"]*"|'[^']*'|[^\s"']+)/gi;
const reEmail = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;
const reIPv4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const reIPv6 = /[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*/g;
const reHomeUnix = /\/(?:home|Users)\/[^/\s"'\\:]+/g;
const reHomeWin = /[A-Z]:[\\/]+Users[\\/]+[^\\/\s"':]+/gi;
const reLong = /[A-Za-z0-9+/_=-]{32,}/g;

// ---- manar-edge internal/door/scan.go: the key detectors DOOR uses ----

const passKey =
  '(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\\b';
const jsonStr = '(?:[^"\\\\]|\\\\.)*';

interface Detector {
  kind: string;
  re: RegExp;
  group: number;
  accept?: (v: string) => boolean;
}

const detectors: Detector[] = [
  {
    kind: 'private_key',
    re: new RegExp(
      `-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:${jsonStr}?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|${jsonStr})`,
      'gd',
    ),
    group: 0,
  },
  {
    kind: 'aws_access_key',
    re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/dg,
    group: 0,
  },
  { kind: 'anthropic_key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/dg, group: 0 },
  {
    kind: 'openai_key',
    re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/dg,
    group: 0,
  },
  {
    kind: 'github_token',
    re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})/dg,
    group: 0,
  },
  { kind: 'gitlab_token', re: /\bglpat-[A-Za-z0-9_-]{20,}/dg, group: 0 },
  { kind: 'google_api_key', re: /\bAIza[0-9A-Za-z_-]{35}\b/dg, group: 0 },
  { kind: 'slack_token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/dg, group: 0 },
  { kind: 'stripe_key', re: /\b[sr]k_live_[A-Za-z0-9]{16,}/dg, group: 0 },
  { kind: 'npm_token', re: /\bnpm_[A-Za-z0-9]{36}\b/dg, group: 0 },
  {
    kind: 'pypi_token',
    re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}/dg,
    group: 0,
  },
  {
    kind: 'password',
    re: new RegExp(
      `${passKey}["']?\\s*[:=]\\s*["']([^"'\\s\\\\]{8,})["']`,
      'gid',
    ),
    group: 1,
    accept: (v) => acceptValue(v, 2.5),
  },
  {
    kind: 'password',
    re: new RegExp(`${passKey}["']?\\s*[:=]\\s*([^\\s"',;]{8,})`, 'gid'),
    group: 1,
    accept: (v) => acceptValue(v, 3.0) && classes(v) >= 2,
  },
];

const dottedIdent = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$/;
const codeWords = [
  'getenv',
  'environ',
  'settings',
  'config',
  'secrets.',
  'getpass',
  'input(',
  'prompt',
  'self.',
  'this.',
  'args.',
  'params.',
];
const placeholders = [
  '<',
  '${',
  '{{',
  '$(',
  '%s',
  'xxxx',
  '****',
  '....',
  'your',
  'example',
  'changeme',
  'placeholder',
  'process.env',
  'os.environ',
  'env[',
  'null',
  'none',
  'true',
  'false',
  'undefined',
];

function isPlaceholder(v: string): boolean {
  const l = v.toLowerCase();
  if (placeholders.some((p) => l.includes(p))) return true;
  return [...l].every((c) => c === l[0]);
}

function entropy(v: string): number {
  const chars = [...v];
  const n = new Map<string, number>();
  for (const c of chars) n.set(c, (n.get(c) ?? 0) + 1);
  let h = 0;
  for (const c of n.values()) {
    const p = c / chars.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function classes(v: string): number {
  let lo = false,
    up = false,
    di = false,
    sy = false;
  for (const r of v) {
    if (r >= 'a' && r <= 'z') lo = true;
    else if (r >= 'A' && r <= 'Z') up = true;
    else if (r >= '0' && r <= '9') di = true;
    else sy = true;
  }
  return [lo, up, di, sy].filter(Boolean).length;
}

function acceptValue(v: string, minEntropy: number): boolean {
  if (isPlaceholder(v) || dottedIdent.test(v) || /[()[\]{}<>$]/.test(v))
    return false;
  const l = v.toLowerCase();
  if (codeWords.some((w) => l.includes(w))) return false;
  return entropy(v) >= minEntropy;
}

/** door.Scan: each secret becomes [MANAR-MASKED:kind]; overlaps merge, the earliest wins. */
function doorScan(s: string): string {
  const spans: Array<{ start: number; end: number; kind: string }> = [];
  for (const d of detectors) {
    d.re.lastIndex = 0;
    for (const m of s.matchAll(d.re)) {
      const idx = m.indices?.[d.group];
      if (!idx) continue;
      const v = s.slice(idx[0], idx[1]);
      if (d.accept && !d.accept(v)) continue;
      spans.push({ start: idx[0], end: idx[1], kind: d.kind });
    }
  }
  if (spans.length === 0) return s;
  spans.sort((a, b) => a.start - b.start); // stable, like sort.SliceStable
  let out = '';
  let pos = 0;
  for (const sp of spans) {
    if (sp.start < pos) continue;
    out += s.slice(pos, sp.start) + `[MANAR-MASKED:${sp.kind}]`;
    pos = sp.end;
  }
  return out + s.slice(pos);
}

// ---- manar-edge internal/telemetry/redact.go ----

/** Drops user:password@, the query string and the fragment. */
function stripURL(raw: string): string {
  let u = raw;
  const q = u.search(/[?#]/);
  if (q >= 0) u = u.slice(0, q);
  const i = u.indexOf('://');
  const slash = u.indexOf('/', i + 3);
  const authority = slash < 0 ? u.slice(i + 3) : u.slice(i + 3, slash);
  const at = authority.lastIndexOf('@');
  if (at >= 0) u = u.slice(0, i + 3) + u.slice(i + 3 + at + 1);
  return u;
}

function looksRandom(v: string): boolean {
  const h = entropy(v);
  const n = [/[a-z]/.test(v), /[A-Z]/.test(v), /[0-9]/.test(v)].filter(
    Boolean,
  ).length;
  if ((v.match(/\//g)?.length ?? 0) >= 2) return n === 3 && h >= 4.0;
  return n >= 2 && h >= 3.5;
}

function redactSecrets(input: string): string {
  let s = input.length > MAX_INPUT ? input.slice(0, MAX_INPUT) : input;
  s = s.replace(rePEM, REDACTED);
  s = s.replace(reJWT, REDACTED);
  s = s.replace(reURL, stripURL);
  s = doorScan(s);
  s = s.replace(reMask, REDACTED);
  s = s.replace(reBearer, `$1 ${REDACTED}`);
  s = s.replace(reFlag, `$1${REDACTED}`);
  s = s.replace(reAssign, `$1$2${REDACTED}`);
  s = s.replace(reIPv4, (m) => (isIPv4(m) ? '<ip>' : m));
  s = s.replace(reIPv6, (m) => {
    const a = m.replace(/^\.+|\.+$/g, '');
    return isIPv6(a) ? '<ip>' : m;
  });
  s = s.replace(reEmail, '<email>');
  return s.replace(reLong, (m) => (looksRandom(m) ? REDACTED : m));
}

/** What may be stored of a command, path or URL a device sent for a decision. */
export function redactForStorage(s: string): string {
  const out = redactSecrets(s).replace(reHomeUnix, '~').replace(reHomeWin, '~');
  const chars = [...out];
  return chars.length <= MAX_SAMPLE ? out : chars.slice(0, MAX_SAMPLE).join('');
}
