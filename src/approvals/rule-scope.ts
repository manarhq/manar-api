import { resourceAliases, resourceKindFor } from '../policy/resource-aliases';

/**
 * The narrow target a repeated approval or a learning suggestion is turned into (decision 37):
 * a folder for file paths, a web origin for fetches, the exact `server/tool` for MCP. Commands
 * have no scope: they are never offered. If anything about a resource is unusual, there is no
 * scope and no match: the person is asked again (fail closed).
 *
 * Paths are stored and matched as the real absolute, canonical prefix of the folder (owner
 * included: `/home/sara/proj/src/`, `c:/work/app/`). Nothing is rewritten to `~`; a grant for one
 * person's folder can never match another person's. A prefix always ends in `/`, so
 * `/proj/src/` does not match `/proj/src-secrets/`.
 */

/** The generic `mcp` and `webfetch` actions carry names and URLs, not file paths. */
const kindOf = (toolId: string, a: string) =>
  a === 'mcp' || a === 'webfetch' ? 'other' : resourceKindFor(toolId, a);

// ---------------------------------------------------------------- paths

/** A drive path, either slash. Windows names are case-insensitive, so they are lower-cased. */
const DRIVE = /^[a-zA-Z]:[\\/]/;
/** Control, format (bidi overrides) and separator characters. */
const BAD_CHARS = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
/** Windows device names, which name a device whatever the extension. */
const DEVICE = /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i;
const WIN_BAD = /[<>"|?*]/;
/** Places a task folder is never: system folders and the root user's home. */
const SYSTEM = [
  '/root',
  '/etc',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/var',
  '/usr',
  '/bin',
  '/sbin',
  '/lib',
  '/lib64',
  '/opt',
  '/private',
  '/run',
  '/tmp',
  '/snap',
  'c:/windows',
  'c:/program files',
  'c:/program files (x86)',
  'c:/programdata',
];

/**
 * The absolute canonical form of a path, or null. Null for: relative paths, UNC, `..` anywhere,
 * alternate data streams (`:`), 8.3 short names (`PROGRA~1`), trailing dots or spaces, device
 * names, control characters, `%`, and backslashes in a non-Windows path.
 */
export function canonicalAbsolute(raw: string): string | null {
  if (raw.length === 0 || raw.length > 2048) return null;
  const win = DRIVE.test(raw);
  let p = raw;
  if (win) p = p.replace(/\\/g, '/').toLowerCase();
  else if (!p.startsWith('/') || p.startsWith('//') || p.includes('\\'))
    return null; // relative, UNC (`//server`, `\\server`), or an ambiguous backslash
  if (BAD_CHARS.test(p) || p.includes('%') || p.includes('\u0000')) return null;
  p = p.normalize('NFC');
  const root = win ? p.slice(0, 3) : '/';
  const rest = p.slice(root.length);
  const segs: string[] = [];
  for (const s of rest.split('/')) {
    if (s === '' || s === '.') continue;
    if (s === '..') return null; // never resolve a climb: ask instead
    if (win && (s.includes(':') || WIN_BAD.test(s) || DEVICE.test(s)))
      return null;
    if (win && /~\d/.test(s)) return null; // 8.3 short name
    if (/[. ]$/.test(s)) return null; // Windows ignores trailing dots and spaces
    segs.push(s);
  }
  return root + segs.join('/');
}

const blockedAlias = (a: string) =>
  a.startsWith('secret-file:') ||
  a.startsWith('unsafe-path:') ||
  a.startsWith('unsafe-command:');

/** Home-folder shapes: `/home/<user>`, `/Users/<user>`, `c:/users/<user>`. */
function homeDepth(dir: string): number {
  const m = /^(\/home\/|\/users\/|c:\/users\/)/i.exec(dir);
  return m ? m[0].split('/').filter(Boolean).length + 1 : 0;
}

function folderScope(resource: string): string | null {
  const path = canonicalAbsolute(resource);
  if (!path || resourceAliases(resource, 'path').some(blockedAlias))
    return null;
  const cut = path.lastIndexOf('/');
  const dir = path.slice(0, cut + 1);
  const lower = dir.toLowerCase();
  if (SYSTEM.some((s) => lower === `${s}/` || lower.startsWith(`${s}/`)))
    return null;
  const segs = dir.split('/').filter(Boolean);
  const root = DRIVE.test(dir) ? 1 : 0; // the drive letter is not a folder
  const depth = segs.length - root;
  // A folder inside a project, not a home folder or a drive root: at least `/home/u/proj/`.
  const home = homeDepth(dir);
  if (depth < 2 || (home > 0 && segs.length < home + 1)) return null;
  // A dot-folder directly under a home folder (`.ssh`, `.config`) is not a project.
  if (home > 0 && segs[home]!.startsWith('.')) return null;
  return `${dir}*`;
}

function pathMatches(pattern: string, resource: string): boolean {
  const path = canonicalAbsolute(resource);
  if (!path || !pattern.endsWith('/*')) return false;
  if (resourceAliases(resource, 'path').some(blockedAlias)) return false;
  return path.startsWith(pattern.slice(0, -1));
}

// ---------------------------------------------------------------- web

/**
 * The origin of a web resource that is already canonical, or null. The raw text must be exactly
 * what a URL parser would make of it: lower-case `https`, an ASCII lower-case host with no
 * userinfo, backslash, whitespace, control character, percent-encoding or punycode, a port only
 * if it is not the default, and a path that starts with `/`.
 */
export function canonicalOrigin(raw: string): string | null {
  if (raw.length === 0 || raw.length > 2048) return null;
  if (/[\\\s\p{Cc}\p{Cf}]/u.test(raw)) return null;
  const m = /^https:\/\/([^/?#]*)/.exec(raw);
  if (!m) return null;
  const authority = m[1]!;
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[1-9][0-9]{0,4})?$/.test(authority))
    return null; // userinfo `@`, `%`, non-ASCII, IPv6 brackets, trailing dot, upper case
  const host = authority.split(':')[0]!;
  if (host.split('.').some((l) => l.startsWith('xn--') || l === ''))
    return null;
  if (authority.endsWith(':443')) return null; // the default port is never written
  const origin = `https://${authority}`;
  if (!raw.startsWith(`${origin}/`)) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:' || u.host !== authority) return null;
  } catch {
    return null;
  }
  return origin;
}

// ---------------------------------------------------------------- public

export function scopeFor(
  toolId: string,
  actionId: string,
  resource: string,
): string | null {
  const a = actionId.toLowerCase();
  const kind = kindOf(toolId, a);
  if (kind === 'command') return null;
  if (kind === 'other') {
    if (a === 'webfetch') {
      const o = canonicalOrigin(resource);
      return o ? `${o}/*` : null;
    }
    // mcp: `server/tool`, exact (no `*`, so it can never widen).
    return /^[\w.@-]+\/[\w.@:-]+$/.test(resource) ? resource : null;
  }
  return folderScope(resource);
}

/** True when `resource` is inside `pattern` (a scope from `scopeFor`). Anything odd is no match. */
export function scopeMatches(
  pattern: string,
  toolId: string,
  actionId: string,
  resource: string,
): boolean {
  const a = actionId.toLowerCase();
  const kind = kindOf(toolId, a);
  if (kind === 'command') return false;
  if (kind === 'other') {
    if (a === 'webfetch') {
      const o = canonicalOrigin(resource);
      return o !== null && `${o}/*` === pattern;
    }
    return pattern === resource;
  }
  return pathMatches(pattern, resource);
}
