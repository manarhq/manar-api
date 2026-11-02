import { CREDENTIAL_PATTERNS } from '../common/dlp/dlp-classification';

/** Longest sample kept, after redaction. */
export const MAX_SAMPLE_CHARS = 512;

// Bounded on both sides: no nested unbounded quantifiers (ReDoS).
const SECRET_WORD =
  '[A-Za-z0-9_.-]{0,64}(?:key|token|secret|passw(?:or)?d|pwd|credential|auth)[A-Za-z0-9_.-]{0,64}';
// Well-known key shapes the generic DLP list does not carry.
const KEY_SHAPES: RegExp[] = [
  /\b(?:sk|pk|rk)[-_](?:live|test|ant|proj)?[-_]?[A-Za-z0-9_-]{16,}/g,
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat|glpat|xox[abprs])[-_][A-Za-z0-9_-]{16,}/g,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  /\bAIza[A-Za-z0-9_-]{30,}/g,
];
const ASSIGNMENT = new RegExp(
  `\\b(${SECRET_WORD})(["']?\\s*[=:]\\s*)("[^"]{0,512}"|'[^']{0,512}'|[^\\s"',}]{1,512})`,
  'gi',
);
// Authorization headers: scheme and credential. Digest carries spaces and quotes, so it goes to the end of the line.
const AUTH_HEADER =
  /\b((?:proxy-)?authorization\s*[:=]\s*)(?:digest\s+[^\r\n]{0,512}|(?:(?:basic|bearer|token)\s+)?[^\s"']{1,512})/gi;
// --password x, --token=x, --secret x, --api-key x ...
const FLAG_SECRET =
  /(--?(?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|auth[-_]?token|client[-_]?secret)[\w-]{0,32})(=|\s+)("[^"]{0,512}"|'[^']{0,512}'|[^\s"']{1,512})/gi;
// mysql-style `-pSECRET` (attached) and `sshpass -p SECRET`.
const MYSQL_P =
  /\b((?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&\n]{0,200}?\s)-p(?!\s)[^\s"']{1,256}/gi;
const SSHPASS_P = /\b(sshpass\s+(?:-\w+\s+){0,3}-p\s*)[^\s"']{1,256}/gi;
// curl -u user:pass, --user user:pass
const USER_PASS =
  /(\s(?:-u|--user|--proxy-user)(?:=|\s+))(?:"[^"]{0,256}:[^"]{0,256}"|'[^']{0,256}:[^']{0,256}'|[^\s"':]{1,128}:[^\s"']{1,256})/gi;
// scheme://user:pass@host
const URL_USERINFO = /(\b[a-z][a-z0-9+.-]{1,16}:\/\/)[^\s/@"']{1,256}@/gi;
const URL_QUERY = /(\bhttps?:\/\/[^\s?#"']*)[?#][^\s"']*/gi;
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;
const IPV4 =
  /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const H = '[0-9A-Fa-f]{1,4}';
const IPV6 = new RegExp(
  `(?<![\\w:])(?:(?:${H}:){7}${H}|(?:${H}:){1,7}:(?:${H}(?::${H}){0,6})?|::(?:${H}(?::${H}){0,6})?)(?![\\w:])`,
  'g',
);
const HOME = /(?:\/home\/|\/Users\/|[A-Za-z]:\\Users\\)([^/\\\s"']+)/g;
// 32+ chars of key alphabet with both a letter and a digit.
const LONG_TOKEN = /[A-Za-z0-9_+=-]{32,}/g;

export const REDACTED = '<redacted>';

const SECRET_KEY = new RegExp(SECRET_WORD, 'i');
/** A property name that looks like it holds a secret (bounded, same words as the assignment rule). */
export const isSecretKey = (k: string): boolean =>
  k.length <= 128 && SECRET_KEY.test(k);

/**
 * Defence in depth: the device redacts first, the api does it again. Home dir -> `~`, the user name
 * found there -> `<user>`, emails, IP addresses, URL query strings and fragments, anything that
 * looks like a key, token or `KEY=value` secret, and long high-entropy strings. Capped at 512 chars.
 */
export function redactText(input: string, max = MAX_SAMPLE_CHARS): string {
  // Bound the work before any regex runs; what we keep is capped at `max` anyway.
  let s = input.length > max * 4 ? input.slice(0, max * 4) : input;
  for (const [, re] of CREDENTIAL_PATTERNS) s = s.replace(re, REDACTED);
  for (const re of KEY_SHAPES) s = s.replace(re, REDACTED);
  s = s
    .replace(AUTH_HEADER, `$1${REDACTED}`)
    .replace(MYSQL_P, `$1-p${REDACTED}`)
    .replace(SSHPASS_P, `$1${REDACTED}`)
    .replace(USER_PASS, `$1${REDACTED}`)
    .replace(FLAG_SECRET, `$1$2${REDACTED}`)
    .replace(URL_USERINFO, `$1${REDACTED}@`);
  s = s.replace(
    ASSIGNMENT,
    (_m, k: string, sep: string) => `${k}${sep}${REDACTED}`,
  );
  s = s.replace(LONG_TOKEN, (t) =>
    /[A-Za-z]/.test(t) && /\d/.test(t) ? REDACTED : t,
  );
  s = s.replace(URL_QUERY, '$1');
  s = s.replace(EMAIL, '<email>').replace(IPV4, '<ip>').replace(IPV6, '<ip>');
  const users = new Set<string>();
  s = s.replace(HOME, (_m, user: string) => {
    users.add(user);
    return '~';
  });
  for (const u of users)
    if (u.length > 2)
      s = s.replace(
        new RegExp(
          `(?<![A-Za-z0-9_])${u.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9_])`,
          'g',
        ),
        '<user>',
      );
  return s.length > max ? s.slice(0, max) : s;
}
