import {
  HOST_CLAUDE_CODE_ACTIONS,
  HOST_CLAUDE_CODE_TOOL,
  KNOWN_HOST_TOOL_IDS,
} from '../tools/host-actions';

/**
 * Policy resource patterns are prefix-only (trailing `*`). A prefix cannot say "any user's
 * ~/.ssh" or "any .env file", so each request resource also gets deterministic alias strings
 * and a rule matches when its pattern matches the raw resource or any alias.
 *
 * Kinds. `path` is the default and the fail-closed choice: unknown tool or unknown action is a
 * path. `command` and `other` are used only for host tools in the catalogue
 * (src/tools/host-actions.ts).
 *
 * Path: canonicalised (backslashes to `/`, `//` and `.` collapse, `..` resolved; drive paths
 * lower-cased and treated as rooted at `x:/`), then
 *  - `C:\Users\x\`, `/home/x/`, `/Users/x/`, `/root/` become `~/`
 *  - a secret-looking name or a known secret directory gives `secret-file:<name>`, whitespace or
 *    not
 *  - a `..` that climbs out of its root (or the home folder) gives `unsafe-path:traversal`
 * Command: split like a POSIX shell (quotes, backslash escapes, operators). Every word gets the
 * secret-file check. A glob, brace, `$` or backtick that the shell would expand gives
 * `unsafe-command:expansion`, because the real path is not knowable from the text.
 * Other (URLs, tool names): no aliases.
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

export function resourceKindFor(
  toolId: string,
  actionId: string,
): ResourceKind {
  const a = actionId.toLowerCase();
  if (toolId === HOST_CLAUDE_CODE_TOOL) {
    return (
      HOST_CLAUDE_CODE_ACTIONS.find((x) => x.name === a)?.resourceKind ?? 'path'
    );
  }
  if (KNOWN_HOST_TOOL_IDS.includes(toolId) && COMMAND_ACTIONS.has(a))
    return 'command';
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

/** Resolves `.` and `..` over a root. A `..` with nothing left to pop is a climb out: escapes. */
function resolveSegments(path: string): { segs: string[]; escapes: boolean } {
  const segs: string[] = [];
  let escapes = false;
  for (const s of path.split('/')) {
    if (s === '' || s === '.') continue;
    if (s === '..') {
      if (segs.length) segs.pop();
      else escapes = true;
    } else segs.push(s);
  }
  return { segs, escapes };
}

/** Canonical form of a path, plus whether any `..` was clamped at a root or climbed out. */
export function canonicalPath(raw: string): { path: string; escapes: boolean } {
  const p = raw.trim().replace(/\\/g, '/');
  const drive = /^([a-z]):(.*)$/i.exec(p);
  let root: string;
  let rest: string;
  if (drive) {
    root = `${drive[1]!.toLowerCase()}:/`;
    rest = drive[2]!.toLowerCase();
  } else if (p === '~' || p.startsWith('~/')) {
    root = '~/';
    rest = p.slice(1);
  } else if (p.startsWith('/')) {
    root = '/';
    rest = p;
  } else {
    const r = resolveSegments(p);
    return { path: r.segs.join('/'), escapes: r.escapes };
  }
  const { segs, escapes } = resolveSegments(rest);
  let path = root + segs.join('/');
  if (root !== '~/') {
    for (const re of HOME_PREFIXES) {
      if (re.test(path + '/')) {
        path = (path + '/').replace(re, '~/').replace(/\/$/, '');
        break;
      }
    }
  }
  return { path, escapes };
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
    SECRET_DIRS.some((d) => (lowered + '/').startsWith(d))
  ) {
    into.add(`secret-file:${name.toLowerCase()}`);
  }
}

/**
 * POSIX-shell words. Handles single and double quotes and backslash escapes; `;|&<>()` and
 * newlines end a word. `expands` is true when an unquoted `* ? [ ] { }`, or a `$` or backtick
 * outside single quotes, is present: the shell would substitute something we cannot see.
 */
export function shellWords(cmd: string): { words: string[]; expands: boolean } {
  const words: string[] = [];
  let cur = '';
  let has = false;
  let expands = false;
  const end = () => {
    if (has) words.push(cur);
    cur = '';
    has = false;
  };
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (c === "'") {
      has = true;
      const j = cmd.indexOf("'", i + 1);
      const stop = j === -1 ? cmd.length : j;
      cur += cmd.slice(i + 1, stop);
      i = stop;
    } else if (c === '"') {
      has = true;
      i++;
      for (; i < cmd.length && cmd[i] !== '"'; i++) {
        const d = cmd[i]!;
        if (
          d === '\\' &&
          i + 1 < cmd.length &&
          '"\\$`\n'.includes(cmd[i + 1]!)
        ) {
          cur += cmd[++i];
        } else {
          if (d === '$' || d === '`') expands = true;
          cur += d;
        }
      }
    } else if (c === '\\') {
      has = true;
      if (i + 1 < cmd.length) cur += cmd[++i];
    } else if (/\s|[;|&<>()]/.test(c)) {
      end();
    } else {
      if ('*?[]{}$`'.includes(c)) expands = true;
      has = true;
      cur += c;
    }
  }
  end();
  return { words, expands };
}

export function resourceAliases(
  resource: string,
  kind: ResourceKind = 'path',
): string[] {
  const out = new Set<string>();
  if (kind === 'path') {
    pathAliases(resource, out);
  } else if (kind === 'command') {
    const { words, expands } = shellWords(resource);
    if (expands) out.add('unsafe-command:expansion');
    for (const w of words) {
      const found = new Set<string>();
      pathAliases(w, found);
      for (const a of found) if (a.startsWith('secret-file:')) out.add(a);
    }
  }
  return [...out];
}
