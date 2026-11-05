/**
 * A conservative classifier for shell commands (friction track, 5 Nov 2026). It answers one
 * question: is this command CLEARLY safe? `read-only` commands only look at files inside the
 * working tree; `dev-loop` commands run the project's own test, lint, build or typecheck.
 * Anything else, including everything this file does not understand, returns `null` and keeps its
 * catalogue risk (70 for a shell command).
 *
 * Deterministic and fail-closed:
 * - exact argv parsing over a closed alphabet: no quote, operator, expansion, substitution,
 *   environment prefix, `~` or `\`;
 * - the binary is a bare name (an absolute path or an alias is not trusted);
 * - a per-tool allowlist of known-harmless flags; an unknown flag, or `--`, is `null`;
 * - every operand and every `=value` must be a relative path inside the working tree: no
 *   absolute or drive path, no `..`, and no secret-looking name (`.env*`, `*.pem`, `*.key`,
 *   `id_*`, `.ssh`, `.aws`, `.npmrc`, `credentials*`, `*.kdbx`, ...). WARDEN's secret-touch
 *   alerts remain the backstop for what a search finds inside the tree.
 *
 * `git` is deliberately NOT classified: its read commands can run code named in repository
 * config (core.fsmonitor, core.pager, external diff, textconv, filters) and Manar cannot force
 * override flags on a command the AI tool runs. See the plan: a later edge-side check.
 *
 * It lowers a score. Policy rules (DENY, APPROVAL_REQUIRED, secrets) and the kill switches are
 * evaluated regardless of it.
 */
export type CommandClass = 'read-only' | 'dev-loop';

/** Scores for a classified command: both stay under the device "console only" line (50). */
export const COMMAND_RISK: Record<CommandClass, number> = {
  'read-only': 20,
  'dev-loop': 30,
};

/** Letters, digits and the punctuation of relative paths and flags. */
const PLAIN = /^[A-Za-z0-9_@%+=:,./-]+$/;

const SENSITIVE =
  /(^|[/=])(\.env[^/]*|[^/]*\.(pem|key|pfx|p12|kdbx|tfstate)|id_[^/]*|\.ssh|\.aws|\.gnupg|\.kube|\.azure|\.docker|\.git|\.npmrc|\.netrc|\.pypirc|credentials[^/]*)(\/|=|$)/i;

/** A value that is a relative path (or a bare word/number) inside the tree and not secret. */
function inTree(v: string): boolean {
  if (v.length === 0 || !PLAIN.test(v)) return false;
  if (v.startsWith('/') || /^[A-Za-z]:/.test(v)) return false;
  if (v.split('/').includes('..')) return false;
  // `a=/etc/x` or `a=../x` inside a value
  if (
    v.includes('=') &&
    !v
      .split('=')
      .slice(1)
      .every((x) => x === '' || inTree(x))
  )
    return false;
  return !SENSITIVE.test(v);
}

interface Spec {
  /** Flags that take no value: `-n`, `--ignore-case`. */
  flags: readonly string[];
  /** Letters that may be combined after one dash (`-la`). */
  combine?: string;
  /** Flags whose value is the next token (`-A 3`, `-name x`); `-A3` and `--x=3` also work. */
  valued?: readonly string[];
  /** `-5` (head/tail). */
  numeric?: boolean;
}

/** True when every token of `args` is an allowed flag, a flag value or an in-tree operand. */
function parse(args: string[], spec: Spec): boolean {
  const valued = new Set(spec.valued ?? []);
  const flags = new Set(spec.flags);
  for (let i = 0; i < args.length; i++) {
    const t = args[i]!;
    if (t === '-' || t === '--') return false;
    if (!t.startsWith('-')) {
      if (!inTree(t)) return false;
      continue;
    }
    const eq = t.indexOf('=');
    const name = eq === -1 ? t : t.slice(0, eq);
    const attached = eq === -1 ? '' : t.slice(eq + 1);
    if (flags.has(name)) {
      if (eq !== -1 && !inTree(attached)) return false;
      continue;
    }
    if (valued.has(name)) {
      const v = eq === -1 ? args[++i] : attached;
      if (v === undefined || !inTree(v)) return false;
      continue;
    }
    if (spec.numeric && /^-\d+$/.test(t)) continue;
    // `-A3`, `-n5`
    const m = /^(-[A-Za-z])(\d+)$/.exec(t);
    if (m && valued.has(m[1]!)) continue;
    if (
      spec.combine &&
      /^-[A-Za-z]{2,}$/.test(t) &&
      [...t.slice(1)].every((c) => spec.combine!.includes(c))
    )
      continue;
    return false;
  }
  return true;
}

const SPECS: Record<string, Spec> = {
  ls: {
    flags: [
      '-a',
      '-A',
      '-l',
      '-h',
      '-1',
      '-R',
      '-t',
      '-r',
      '-S',
      '-d',
      '-F',
      '--all',
      '--human-readable',
    ],
    combine: 'aAlh1RtrSdF',
  },
  cat: { flags: ['-n', '-b', '-s', '-E', '-T', '--number'], combine: 'nbsET' },
  head: {
    flags: ['-q', '-v'],
    valued: ['-n', '-c', '--lines', '--bytes'],
    numeric: true,
  },
  tail: {
    flags: ['-q', '-v', '-f'],
    valued: ['-n', '-c', '--lines', '--bytes'],
    numeric: true,
  },
  grep: {
    flags: [
      '-i',
      '-n',
      '-r',
      '-l',
      '-L',
      '-c',
      '-v',
      '-w',
      '-x',
      '-F',
      '-E',
      '-H',
      '-h',
      '-s',
      '-q',
      '-o',
      '--ignore-case',
      '--line-number',
      '--recursive',
      '--files-with-matches',
      '--count',
      '--fixed-strings',
      '--word-regexp',
      '--color',
    ],
    combine: 'inrlLcvwxFEHhsqo',
    valued: [
      '-A',
      '-B',
      '-C',
      '-m',
      '-e',
      '--include',
      '--exclude',
      '--exclude-dir',
      '--max-count',
    ],
  },
  rg: {
    flags: [
      '-i',
      '-n',
      '-l',
      '-c',
      '-w',
      '-F',
      '-s',
      '-S',
      '-v',
      '-o',
      '-H',
      '-N',
      '--no-heading',
      '--heading',
      '--line-number',
      '--files-with-matches',
      '--count',
      '--ignore-case',
      '--fixed-strings',
      '--word-regexp',
      '--smart-case',
      '--files',
    ],
    combine: 'inlcwFsSvoHN',
    valued: [
      '-A',
      '-B',
      '-C',
      '-m',
      '-e',
      '-t',
      '-T',
      '-g',
      '--type',
      '--max-count',
      '--glob',
    ],
  },
  find: {
    // Expression primaries, all read-only. No -L, -exec, -execdir, -ok, -delete, -fprint, -fls.
    flags: ['-print'],
    valued: ['-name', '-iname', '-path', '-ipath', '-maxdepth', '-mindepth'],
  },
};

/** `-type` takes one of these; everything else is a path pattern. */
const FIND_TYPE = /^[fdl]$/;

function findSafe(args: string[]): boolean {
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-type') {
      if (!FIND_TYPE.test(args[i + 1] ?? '')) return false;
      i++;
    } else rest.push(args[i]!);
  }
  return parse(rest, SPECS.find!);
}

const SCRIPT = /^(test|lint|build|typecheck|check)(:[a-z-]+)?$/;
const writes = /fix|deploy|publish|release|install|write|format/;
const okScript = (s: string) => SCRIPT.test(s) && !writes.test(s);
/** Dev-loop operands: relative paths or test names, never a flag. */
const operands = (args: string[]) =>
  args.every((a) => !a.startsWith('-') && inTree(a));

const GO: Spec = {
  flags: ['-v', '-race', '-short', '-cover'],
  valued: ['-count', '-run', '-timeout'],
};
const CARGO: Spec = {
  flags: [
    '--release',
    '--quiet',
    '-q',
    '--all',
    '--workspace',
    '--all-targets',
    '--lib',
    '--bins',
    '--tests',
  ],
  valued: ['-p', '--package'],
};
const PYTEST: Spec = {
  flags: ['-v', '-vv', '-q', '-x', '-s', '--tb'],
  combine: 'vqxs',
  valued: ['-k'],
};

/** Returns the class of a command that is clearly safe, or null (keep asking). */
export function classifyCommand(command: string): CommandClass | null {
  if (command.length === 0 || command.length > 300) return null;
  // One line, single spaces, closed alphabet: no operator, quote, expansion or substitution.
  if (command !== command.trim() || / {2}/.test(command)) return null;
  const argv = command.split(' ');
  if (!argv.every((t) => PLAIN.test(t))) return null;
  const [bin, ...args] = argv as [string, ...string[]];
  // A bare binary name only; `/bin/ls`, `./ls` or `FOO=bar ls` are not trusted.
  if (bin.includes('/') || bin.includes('=')) return null;

  switch (bin) {
    case 'pwd':
      return args.length === 0 ? 'read-only' : null;
    case 'ls':
    case 'cat':
    case 'head':
    case 'tail':
    case 'grep':
    case 'rg':
      return parse(args, SPECS[bin]!) ? 'read-only' : null;
    case 'find':
      return findSafe(args) ? 'read-only' : null;
    case 'npm':
    case 'pnpm':
    case 'yarn': {
      const [a, ...rest] = args;
      if (!a) return null;
      if (a === 'run' || a === 'run-script') {
        const [s, ...more] = rest;
        return s && okScript(s) && operands(more) ? 'dev-loop' : null;
      }
      if (bin === 'npm' && a === 't') return operands(rest) ? 'dev-loop' : null;
      return okScript(a) && operands(rest) ? 'dev-loop' : null;
    }
    case 'go': {
      const [a, ...rest] = args;
      return a && ['test', 'build', 'vet'].includes(a) && parse(rest, GO)
        ? 'dev-loop'
        : null;
    }
    case 'cargo': {
      const [a, ...rest] = args;
      return a &&
        ['test', 'build', 'check', 'clippy'].includes(a) &&
        parse(rest, CARGO)
        ? 'dev-loop'
        : null;
    }
    case 'pytest':
      return parse(args, PYTEST) ? 'dev-loop' : null;
    default:
      return null;
  }
}
