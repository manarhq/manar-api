/**
 * A conservative classifier for shell commands (friction track, 5 Nov 2026). It answers one
 * question: is this command CLEARLY read-only? `read-only` commands only look at files inside the
 * working tree. Anything else, including everything this file does not understand, returns
 * `null` and keeps its catalogue risk (70 for a shell command).
 *
 * Test, lint, build and typecheck runs are NOT classified: they run code the repository controls
 * (scripts, build.rs, test hooks, plugins), so they keep asking like any other program.
 *
 * Deterministic and fail-closed:
 * - exact argv parsing over a closed alphabet: no quote, operator, expansion, substitution,
 *   environment prefix, `~`, `\`, `%` (cmd variables) or `:` (PowerShell `env:`, drive letters,
 *   alternate data streams); no token starts with `@` or `=`;
 * - the binary is a bare name (an absolute path or an alias is not trusted);
 * - a per-tool allowlist of known-harmless flags; an unknown flag, or `--`, is `null`;
 * - every operand and every `=value` must be a relative path inside the working tree: no
 *   absolute or drive path, no `..`, no dot-file or dot-folder (`.env`, `.git`, `.ssh`; a lone `.`
 *   is the working folder), and no secret-looking name;
 * - anything recursive (`grep -r`, `rg`, `find`, `ls -R`) must name its folder explicitly;
 * - WARDEN's secret-touch alerts remain the backstop for what a search finds inside the tree.
 *
 * `git` is deliberately NOT classified: its read commands can run code from repository config
 * (core.fsmonitor, core.pager, external diff, textconv, filters) and Manar cannot force override
 * flags on a command the AI tool runs. Later, edge-side: WARDEN checks the repo's effective git
 * config and marks git reads low risk only when none of those keys are set.
 *
 * It lowers a score. Policy rules (DENY, APPROVAL_REQUIRED, secrets) and the kill switches are
 * evaluated regardless of it.
 */
export type CommandClass = 'read-only';

/**
 * Below the high-risk line (50) but above the device risk ceiling (20): in a workspace without a
 * matching rule such a command still asks, so it never becomes a silent ALLOW by classification
 * alone. Learning mode may quiet it under its own rules.
 */
export const COMMAND_RISK: Record<CommandClass, number> = { 'read-only': 30 };

/** Letters, digits and the punctuation of relative paths and flags. */
const PLAIN = /^[A-Za-z0-9_+,./=-]+$/;

const SENSITIVE = new RegExp(
  '(^|[/=])(' +
    [
      '\\.env[^/]*',
      '[^/]*\\.(pem|key|pfx|p12|kdbx|tfstate|ppk|jks|keystore)',
      'id_[^/]*',
      '[^/]*_history',
      '\\.?credentials[^/]*',
      '[^/]*\\.(tfvars|env)',
      '(secrets?|credentials)[^/]*\\.ya?ml',
      'database\\.yml',
      '\\.git-credentials',
      'hosts\\.yml',
      'auth\\.json',
      '\\.vault-token',
      '\\.pgpass',
      '[^/]*kubeconfig[^/]*',
      '\\.kube',
      '\\.netrc',
      '\\.npmrc',
      '\\.pypirc',
      '\\.ssh',
      '\\.aws',
      '\\.gnupg',
      '\\.kube',
      '\\.azure',
      '\\.docker',
      '\\.git',
      '\\.config/gcloud',
      'gcloud',
      'config\\.json',
    ].join('|') +
    ')(/|=|$)',
  'i',
);

/** A value that is a relative path (or a bare word/number) inside the tree and not secret. */
function inTree(v: string): boolean {
  if (v.length === 0 || !PLAIN.test(v)) return false;
  if (v.startsWith('@') || v.startsWith('=')) return false;
  if (v.startsWith('/')) return false;
  const parts = v.split('=');
  // `--name=value`: the value is a path or word too.
  if (parts.length > 1 && !parts.slice(1).every((x) => x === '' || inTree(x)))
    return false;
  for (const seg of parts[0]!.split('/')) {
    if (seg === '..') return false;
    if (seg.startsWith('.') && seg !== '.') return false; // dot-file or dot-folder
  }
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

interface Parsed {
  /** Non-flag tokens, in order. */
  operands: string[];
  /** Every flag seen, normalised (`-rn` gives `-r` and `-n`). */
  seen: Set<string>;
}

/** The allowed flags, values and operands of `args`, or null when any token is not allowed. */
function parse(args: string[], spec: Spec): Parsed | null {
  const valued = new Set(spec.valued ?? []);
  const flags = new Set(spec.flags);
  const out: Parsed = { operands: [], seen: new Set() };
  for (let i = 0; i < args.length; i++) {
    const t = args[i]!;
    if (t === '-' || t === '--') return null;
    if (!t.startsWith('-')) {
      if (!inTree(t)) return null;
      out.operands.push(t);
      continue;
    }
    const eq = t.indexOf('=');
    const name = eq === -1 ? t : t.slice(0, eq);
    const attached = eq === -1 ? '' : t.slice(eq + 1);
    if (flags.has(name)) {
      if (eq !== -1 && !inTree(attached)) return null;
      out.seen.add(name);
      continue;
    }
    if (valued.has(name)) {
      const v = eq === -1 ? args[++i] : attached;
      if (v === undefined || !inTree(v)) return null;
      out.seen.add(name);
      continue;
    }
    if (spec.numeric && /^-\d+$/.test(t)) continue;
    const m = /^(-[A-Za-z])(\d+)$/.exec(t); // `-A3`, `-n5`
    if (m && valued.has(m[1]!)) {
      out.seen.add(m[1]!);
      continue;
    }
    if (
      spec.combine &&
      /^-[A-Za-z]{2,}$/.test(t) &&
      [...t.slice(1)].every((c) => spec.combine!.includes(c))
    ) {
      for (const c of t.slice(1)) out.seen.add(`-${c}`);
      continue;
    }
    return null;
  }
  return out;
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
    flags: ['-q', '-v'],
    valued: ['-n', '-c', '--lines', '--bytes'],
    numeric: true,
  },
  grep: {
    flags: [
      '-i',
      '-n',
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
      '--files-with-matches',
      '--count',
      '--fixed-strings',
      '--word-regexp',
    ],
    combine: 'inlLcvwxFEHhsqo',
    valued: ['-A', '-B', '-C', '-m', '-e', '--max-count'],
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
    valued: ['-A', '-B', '-C', '-m', '-e', '-t', '-T', '--type', '--max-count'],
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
  // The folder is named explicitly: `find -name x` would search the working folder by default.
  if (args.length === 0 || args[0]!.startsWith('-')) return false;
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-type') {
      if (!FIND_TYPE.test(args[i + 1] ?? '')) return false;
      i++;
    } else rest.push(args[i]!);
  }
  const p = parse(rest, SPECS.find!);
  return p !== null && p.operands.length >= 1;
}

/** Returns the class of a command that is clearly safe, or null (keep asking). */
export function classifyCommand(command: string): CommandClass | null {
  if (command.length === 0 || command.length > 300) return null;
  // One line, single spaces, closed alphabet: no operator, quote, expansion or substitution.
  if (command !== command.trim() || / {2}/.test(command)) return null;
  const argv = command.split(' ');
  if (!argv.every((t) => PLAIN.test(t) && !/^[@=]/.test(t))) return null;
  const [bin, ...args] = argv as [string, ...string[]];
  // A bare binary name only; `/bin/ls`, `./ls` or `FOO=bar ls` are not trusted.
  if (bin.includes('/') || bin.includes('=')) return null;

  switch (bin) {
    case 'pwd':
      return args.length === 0 ? 'read-only' : null;
    case 'ls': {
      const p = parse(args, SPECS.ls!);
      // `ls -R` names its folder.
      return p && (!p.seen.has('-R') || p.operands.length >= 1)
        ? 'read-only'
        : null;
    }
    case 'cat':
    case 'head':
    case 'tail': {
      const p = parse(args, SPECS[bin]!);
      return p && p.operands.length >= 1 ? 'read-only' : null;
    }
    case 'grep': {
      const p = parse(args, SPECS.grep!);
      if (!p) return null;
      // The pattern is the first operand unless -e gives it; a file must follow. Recursive grep
      // (-r, -R, --recursive, ...) is not in the alphabet: it reads hidden files such as .env.
      const need = p.seen.has('-e') ? 1 : 2;
      return p.operands.length >= need ? 'read-only' : null;
    }
    case 'rg': {
      const p = parse(args, SPECS.rg!);
      if (!p) return null;
      // rg walks every non-hidden file of a folder, committed secrets included (keys/server.pem,
      // terraform.tfstate), and prints matching lines: it is read-only only when it prints names
      // or counts, never contents.
      const namesOnly = [
        '--files',
        '-l',
        '--files-with-matches',
        '-c',
        '--count',
      ].some((f) => p.seen.has(f));
      if (!namesOnly) return null;
      const need = p.seen.has('--files') || p.seen.has('-e') ? 1 : 2;
      return p.operands.length >= need ? 'read-only' : null;
    }
    case 'find':
      return findSafe(args) ? 'read-only' : null;
    default:
      return null;
  }
}
