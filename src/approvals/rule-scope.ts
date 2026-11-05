import {
  canonicalPath,
  resourceAliases,
  resourceKindFor,
} from '../policy/resource-aliases';

/** The generic `mcp` and `webfetch` actions carry names and URLs, not file paths. */
const kindOf = (toolId: string, a: string) =>
  a === 'mcp' || a === 'webfetch' ? 'other' : resourceKindFor(toolId, a);

/**
 * The narrow target a repeated approval or a learning suggestion is turned into (decision 37):
 * a folder for file paths, a web origin for fetches, the exact `server/tool` for MCP. Commands
 * have no scope: they are never offered. A scope is a prefix ending in `*`.
 */
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
      try {
        const u = new URL(resource);
        return u.protocol === 'https:' ? `${u.origin}/*` : null;
      } catch {
        return null;
      }
    }
    // mcp: `server/tool`, exact (no `*`, so it can never widen).
    return /^[\w.@-]+\/[\w.@:-]+$/.test(resource) ? resource : null;
  }
  return folderScope(resource);
}

function folderScope(resource: string): string | null {
  if (resourceAliases(resource, 'path').some(blockedAlias)) return null;
  const { path, escapes } = canonicalPath(resource);
  if (escapes) return null;
  const cut = path.lastIndexOf('/');
  if (cut <= 0) return null;
  const dir = path.slice(0, cut + 1);
  const root = /^([a-z]:\/|~\/|\/)/.exec(dir)?.[0];
  if (!root) return null;
  const segs = dir.slice(root.length).split('/').filter(Boolean);
  if (segs.length === 0) return null;
  if (root === '~/' ? segs[0]!.startsWith('.') : segs.length < 2) return null;
  return `${dir}*`;
}

const blockedAlias = (a: string) =>
  a.startsWith('secret-file:') ||
  a.startsWith('unsafe-path:') ||
  a.startsWith('unsafe-command:');

/** True when `resource` is inside `pattern` (a scope from `scopeFor`). Never for secrets or `..`. */
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
      try {
        const u = new URL(resource);
        return u.protocol === 'https:' && `${u.origin}/*` === pattern;
      } catch {
        return false;
      }
    }
    return pattern === resource;
  }
  if (!pattern.endsWith('*')) return false;
  if (resourceAliases(resource, 'path').some(blockedAlias)) return false;
  const { path, escapes } = canonicalPath(resource);
  return !escapes && path.startsWith(pattern.slice(0, -1));
}
