import { posix } from 'node:path';

/**
 * Policy resource patterns are prefix-only (trailing `*`). A prefix cannot say "any user's
 * ~/.ssh" or "any .env file", so each request resource also gets deterministic alias strings
 * and a rule matches when its pattern matches the raw resource or any alias.
 *
 * For a file path (the default) the path is canonicalised first: backslashes become `/`, `//`
 * and `/./` collapse, `..` is resolved, drive paths are lower-cased. Then:
 *  - `C:\Users\x\`, `/home/x/`, `/Users/x/`, `/root/` become `~/`
 *  - a secret-looking file name or a known secret directory gives `secret-file:<name>`; this is
 *    ALWAYS computed for a file path, whitespace included
 *  - a path whose `..` climbs out of its root (relative or `~`) gives `unsafe-path:traversal`,
 *    so presets can fail closed on it
 * For a shell command, each token that looks like a path gets the same treatment.
 * Anything else (URLs, tool names) gets no aliases.
 */
export type ResourceKind = 'path' | 'command' | 'other';

const COMMAND_ACTIONS = new Set([
  'bash',
  'shell',
  'sh',
  'powershell',
  'cmd',
  'terminal',
  'run_command',
  'run_terminal_cmd',
  'execute_command',
  'exec',
]);
const OTHER_ACTIONS = new Set([
  'webfetch',
  'websearch',
  'glob',
  'grep',
  'ls',
  'task',
  'todowrite',
]);

export function resourceKindFor(actionId: string): ResourceKind {
  const a = actionId.toLowerCase();
  if (COMMAND_ACTIONS.has(a)) return 'command';
  if (OTHER_ACTIONS.has(a)) return 'other';
  return 'path';
}

const HOME_PREFIXES: readonly RegExp[] = [
  /^[a-z]:\/users\/[^/]+\//,
  /^\/home\/[^/]+\//,
  /^\/users\/[^/]+\//i,
  /^\/root\//,
];
const SECRET_DIRS = [
  '~/.ssh/',
  '~/.aws/',
  '~/.gnupg/',
  '~/.kube/',
  '~/.azure/',
  '~/.docker/',
];
const SECRET_NAME =
  /^(\.env(\..+)?|id_(rsa|ed25519|ecdsa|dsa)|.+\.(pem|key|pfx|p12)|credentials|\.npmrc|\.netrc|\.pypirc|.+\.tfstate)$/i;
const HOME_ROOT = '/__home__';

/** Canonical form of a path, plus whether its `..` climbs out of its root. */
export function canonicalPath(raw: string): { path: string; escapes: boolean } {
  let p = raw.trim().replace(/\\/g, '/');
  if (/^[a-z]:\//i.test(p)) p = p.toLowerCase();
  const home = p === '~' || p.startsWith('~/');
  if (home) p = HOME_ROOT + p.slice(1);
  p = posix.normalize(p.replace(/\/{2,}/g, '/'));
  if (home) {
    if (p !== HOME_ROOT && !p.startsWith(HOME_ROOT + '/')) {
      return { path: p, escapes: true };
    }
    return { path: '~' + p.slice(HOME_ROOT.length), escapes: false };
  }
  const escapes = p === '..' || p.startsWith('../');
  if (!escapes) {
    for (const re of HOME_PREFIXES) {
      if (re.test(p + '/')) {
        p = p.replace(re, '~/');
        break;
      }
    }
  }
  return { path: p, escapes };
}

function pathAliases(raw: string, into: Set<string>): void {
  const { path, escapes } = canonicalPath(raw);
  if (escapes) into.add('unsafe-path:traversal');
  if (path !== raw) into.add(path);
  // Names are compared without trailing dots and spaces, which Windows ignores.
  const name = path.slice(path.lastIndexOf('/') + 1).replace(/[. ]+$/, '');
  const lowered = path.toLowerCase();
  if (
    SECRET_NAME.test(name) ||
    SECRET_DIRS.some((d) => lowered.startsWith(d))
  ) {
    into.add(`secret-file:${name.toLowerCase()}`);
  }
}

export function resourceAliases(
  resource: string,
  kind: ResourceKind = 'path',
): string[] {
  const out = new Set<string>();
  if (kind === 'path') {
    pathAliases(resource, out);
  } else if (kind === 'command') {
    for (const tok of resource.split(/\s+/)) {
      const t = tok.replace(/^["'`;|&<>(]+|["'`;|&<>)]+$/g, '');
      if (t.startsWith('~') || /[\\/]/.test(t)) pathAliases(t, out);
    }
    // A command is not itself a path: drop the canonical-path aliases, keep the markers.
    for (const a of [...out]) {
      if (!a.startsWith('secret-file:') && a !== 'unsafe-path:traversal') {
        out.delete(a);
      }
    }
  }
  return [...out];
}
