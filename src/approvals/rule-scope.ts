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
const WSL_DRIVE = /^\/mnt\/[a-zA-Z]\//;
/** Control, format (bidi overrides) and separator characters. */
const BAD_CHARS = /[\p{Cc}\p{Cf}\u2028\u2029]/u;
/** Windows device names, which name a device whatever the extension. */
const DEVICE = /^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i;
const WIN_BAD = /[<>"|?*]/;
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
  // Windows drives mounted in WSL are Windows files: case-insensitive, same name rules.
  else if (WSL_DRIVE.test(raw)) p = p.toLowerCase();
  else if (!p.startsWith('/') || p.startsWith('//') || p.includes('\\'))
    return null; // relative, UNC (`//server`, `\\server`), or an ambiguous backslash
  if (BAD_CHARS.test(p) || p.includes('%') || p.includes('\u0000')) return null;
  p = p.normalize('NFC');
  const winLike = win || WSL_DRIVE.test(p);
  const root = win ? p.slice(0, 3) : '/';
  const rest = p.slice(root.length);
  const segs: string[] = [];
  for (const s of rest.split('/')) {
    if (s === '' || s === '.') continue;
    if (s === '..') return null; // never resolve a climb: ask instead
    if (winLike && (s.includes(':') || WIN_BAD.test(s) || DEVICE.test(s)))
      return null;
    if (winLike && /~\d/.test(s)) return null; // 8.3 short name
    if (/[. ]$/.test(s)) return null; // Windows ignores trailing dots and spaces
    segs.push(s);
  }
  return root + segs.join('/');
}

const blockedAlias = (a: string) =>
  a.startsWith('secret-file:') ||
  a.startsWith('unsafe-path:') ||
  a.startsWith('unsafe-command:');

/**
 * A folder scope is offered only for a folder inside a recognised user home, at least one level
 * below it: `/home/<u>/`, `/Users/<u>/`, `<drive>:/Users/<u>/` and `/mnt/<drive>/Users/<u>/`
 * (WSL). Everything else (system roots, /tmp, /opt, /var, other mounts, network shares) offers
 * nothing and keeps asking. Structure is compared case-insensitively.
 */
const HOME =
  /^(\/home\/|\/users\/|[a-z]:\/users\/|\/mnt\/[a-z]\/users\/)([^/]+)\/(.+)$/i;
/** Shared and template profiles are not a person's project space. */
const NOT_A_PERSON = /^(shared|public|default|default user|all users|guest)$/i;
/** First folders under a home that hold configuration, app data or persistence. */
const CONFIG_FIRST =
  /^(\.|appdata$|library$|application data$|start menu$|local settings$)/i;
/** Autostart locations, wherever they sit in the path. */
const PERSISTENCE = /startup|launchagents|launchdaemons|autostart|start menu/i;

function folderScope(resource: string): string | null {
  const path = canonicalAbsolute(resource);
  if (!path || resourceAliases(resource, 'path').some(blockedAlias))
    return null;
  const dir = path.slice(0, path.lastIndexOf('/') + 1);
  const m = HOME.exec(dir);
  if (!m || NOT_A_PERSON.test(m[2]!)) return null;
  const below = m[3]!.split('/').filter(Boolean);
  if (below.length === 0 || CONFIG_FIRST.test(below[0]!)) return null;
  if (PERSISTENCE.test(dir)) return null;
  return `${dir}*`;
}
function pathMatches(pattern: string, resource: string): boolean {
  const path = canonicalAbsolute(resource);
  if (!path || !pattern.endsWith('/*')) return false;
  if (resourceAliases(resource, 'path').some(blockedAlias)) return false;
  // A persistence folder inside a granted project is still not covered.
  return path.startsWith(pattern.slice(0, -1)) && !PERSISTENCE.test(path);
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
