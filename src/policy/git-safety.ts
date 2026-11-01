/**
 * Git safety aliases. Given the words of one shell command (already split by the hardened
 * tokenizer in resource-aliases.ts), return `git-unsafe:<kind>` strings that policy rules match.
 *
 * Fails closed. Git accepts unambiguous abbreviations of long options and bundles of short ones,
 * so a long option that is a prefix of a sensitive one IS that option, and on push, reset, branch
 * and rebase any option not on an exact safe list is `ambiguous`. So is a `-c`/environment config
 * that sets anything outside a tiny allow-list (it could define an alias or change push rules),
 * and any subcommand we do not know (it may be a user alias for `push -f`).
 * Text cannot say whether a ref is already pushed, so `reset --hard` is always flagged; a push
 * with no explicit non-default refspec could push the current branch, so it is flagged too.
 */
export const GIT_UNSAFE_KINDS = [
  'force-push',
  'push-default-branch',
  'history-rewrite',
  'branch-delete',
  'ambiguous',
] as const;
export type GitUnsafeKind = (typeof GIT_UNSAFE_KINDS)[number];
type K = GitUnsafeKind;

const DEFAULT_BRANCHES = new Set(['main', 'master', 'trunk']);
const GLOBAL_WITH_VALUE = new Set([
  '-C',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--super-prefix',
  '--exec-path',
  '--attr-source',
]);
const GLOBAL_FLAGS = new Set([
  '-p',
  '-P',
  '--paginate',
  '--no-pager',
  '--bare',
  '--no-replace-objects',
  '--literal-pathspecs',
  '--glob-pathspecs',
  '--noglob-pathspecs',
  '--icase-pathspecs',
  '--no-optional-locks',
  '--no-lazy-fetch',
  '--no-advice',
]);
/** `-c key=value` settings that cannot change what a command does to history. */
const SAFE_CONFIG = /^(user\.(name|email)|color\.[a-z.]+|advice\.[a-z]+)=/i;
const SAFE_SUBCOMMANDS = new Set(
  (
    'add am apply archive bisect blame bundle cat-file check-ignore checkout cherry cherry-pick ' +
    'clean clone commit describe diff difftool fetch format-patch fsck grep help init ' +
    'log ls-files ls-remote ls-tree maintenance merge merge-base mergetool mv notes pull range-diff ' +
    'reflog remote restore rev-list rev-parse revert rm shortlog show show-branch sparse-checkout ' +
    'stash status submodule switch tag version whatchanged worktree lfs'
  ).split(' '),
);

/** Option tables per subcommand: sensitive long names, exact safe long names, safe short letters. */
interface Opts {
  sensitive: Record<string, K[]>;
  safe: string[];
  value: string[]; // long options that take a separate value
  short: string; // safe short letters
}
const PUSH: Opts = {
  sensitive: {
    force: ['force-push'],
    'force-with-lease': ['force-push'],
    'force-if-includes': ['force-push'],
    mirror: ['force-push', 'push-default-branch'],
    delete: ['branch-delete'],
    prune: ['branch-delete'],
    all: ['push-default-branch'],
    branches: ['push-default-branch'],
  },
  safe: [
    'tags',
    'set-upstream',
    'verbose',
    'quiet',
    'dry-run',
    'no-verify',
    'verify',
    'progress',
    'porcelain',
    'atomic',
    'thin',
    'no-thin',
    'follow-tags',
    'no-follow-tags',
    'ipv4',
    'ipv6',
    'signed',
    'no-signed',
    'recurse-submodules',
    'no-recurse-submodules',
    'push-option',
    'repo',
    'receive-pack',
    'exec',
  ],
  // Options with a REQUIRED argument consume the next word (`--recurse-submodules check`).
  value: ['push-option', 'repo', 'receive-pack', 'exec', 'recurse-submodules'],
  short: 'uqnv46o',
};
const RESET: Opts = {
  sensitive: { hard: ['history-rewrite'] },
  safe: [
    'soft',
    'mixed',
    'keep',
    'merge',
    'quiet',
    'patch',
    'refresh',
    'no-refresh',
    'recurse-submodules',
    'no-recurse-submodules',
    'pathspec-from-file',
    'pathspec-file-nul',
  ],
  value: ['pathspec-from-file'],
  short: 'qpN',
};
const BRANCH: Opts = {
  sensitive: { delete: [], force: [] },
  safe: [
    'list',
    'all',
    'remotes',
    'verbose',
    'quiet',
    'show-current',
    'contains',
    'no-contains',
    'merged',
    'no-merged',
    'set-upstream-to',
    'unset-upstream',
    'track',
    'no-track',
    'copy',
    'move',
    'create-reflog',
    'sort',
    'format',
    'color',
    'no-color',
    'column',
    'no-column',
    'points-at',
    'edit-description',
    'omit-empty',
    'ignore-case',
    'abbrev',
    'no-abbrev',
  ],
  value: [
    'set-upstream-to',
    'contains',
    'no-contains',
    'merged',
    'no-merged',
    'sort',
    'format',
    'points-at',
    'abbrev',
  ],
  short: 'arvqlcCmMtuiI',
};
const REBASE: Opts = {
  sensitive: {
    interactive: ['history-rewrite'],
    root: ['history-rewrite'],
    onto: ['history-rewrite'],
    autosquash: ['history-rewrite'],
    exec: ['history-rewrite'],
  },
  safe: [
    'continue',
    'abort',
    'skip',
    'quit',
    'edit-todo',
    'show-current-patch',
    'keep-empty',
    'no-ff',
    'autostash',
    'no-autostash',
    'verbose',
    'quiet',
    'stat',
    'no-stat',
    'signoff',
    'fork-point',
    'no-fork-point',
    'rebase-merges',
    'no-rebase-merges',
    'update-refs',
    'no-update-refs',
    'merge',
    'strategy',
    'strategy-option',
    'force-rebase',
    'no-verify',
    'verify',
    'empty',
    'keep-base',
  ],
  value: ['strategy', 'strategy-option', 'empty'],
  short: 'qvmfksX',
};

/** Result of reading the options of one subcommand. */
interface Parsed {
  kinds: Set<K>;
  pos: string[];
  flags: Set<string>; // canonical long names and short letters seen
}

function parseOpts(args: string[], o: Opts): Parsed {
  const kinds = new Set<K>();
  const pos: string[] = [];
  const flags = new Set<string>();
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--') {
      pos.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith('--')) {
      const name = a.slice(2).split('=')[0]!.toLowerCase();
      const hit = Object.keys(o.sensitive).filter((k) => k.startsWith(name));
      if (hit.length) {
        for (const k of hit) {
          flags.add(k);
          o.sensitive[k]!.forEach((x) => kinds.add(x));
        }
        if (['repo', 'exec', 'onto'].includes(hit[0]!) && !a.includes('=')) i++;
      } else if (o.safe.includes(name)) {
        flags.add(name);
        if (o.value.includes(name) && !a.includes('=')) i++;
      } else kinds.add('ambiguous');
    } else if (/^-[A-Za-z0-9]+$/.test(a)) {
      for (const ch of a.slice(1)) {
        flags.add(ch);
        if (!(o.short.includes(ch) || 'fdDi'.includes(ch)))
          kinds.add('ambiguous');
      }
      if (a.includes('o') && o === PUSH) i++; // -o <push-option>
    } else if (a.startsWith('-')) {
      kinds.add('ambiguous');
    } else pos.push(a);
  }
  return { kinds, pos, flags };
}

function pushKinds(args: string[]): K[] {
  const { kinds, pos, flags } = parseOpts(args, PUSH);
  // `-o` is only a push option, never a mode: it was skipped with its value.
  if (flags.has('f')) kinds.add('force-push');
  if (flags.has('d')) kinds.add('branch-delete');
  const repo = flags.has('repo');
  const refspecs = repo ? pos : pos.slice(1);
  for (const spec of pos) {
    if (spec.startsWith('+')) kinds.add('force-push');
  }
  for (const spec of refspecs) {
    const bare = spec.replace(/^\+/, '');
    if (bare.startsWith(':')) kinds.add('branch-delete');
    if (bare.includes('*')) kinds.add('push-default-branch');
    const colon = bare.lastIndexOf(':');
    let dst = (colon === -1 ? bare : bare.slice(colon + 1)).toLowerCase();
    // HEAD or @ without a destination pushes the current branch, which may be main.
    if (colon === -1 && (dst === 'head' || dst === '@'))
      kinds.add('push-default-branch');
    while (/^(refs\/|heads\/)/.test(dst))
      dst = dst.replace(/^(refs\/|heads\/)/, '');
    if (DEFAULT_BRANCHES.has(dst) || dst === '')
      kinds.add('push-default-branch');
  }
  const tagsOnly = flags.has('tags') && refspecs.length === 0;
  const deleting = kinds.has('branch-delete');
  if (
    refspecs.length === 0 &&
    !tagsOnly &&
    !deleting &&
    !flags.has('dry-run')
  ) {
    kinds.add('push-default-branch'); // no refspec: pushes whatever is configured, maybe main
  }
  return [...kinds];
}

/** Terminal options that only print something. */
const INFO_ONLY = new Set([
  '--version',
  '--help',
  '-h',
  '--html-path',
  '--man-path',
  '--info-path',
  '--exec-path',
]);

/** Skips git's global options. `bad` is true for an option we cannot place. */
function splitGlobal(words: string[]): { i: number; bad: boolean } {
  let i = 1;
  while (i < words.length) {
    const w = words[i]!;
    if (INFO_ONLY.has(w)) return { i: words.length, bad: false };
    if (
      w === '-c' ||
      (w.startsWith('-c') && !w.startsWith('--') && w.length > 2)
    ) {
      const kv = w === '-c' ? (words[i + 1] ?? '') : w.slice(2);
      if (!SAFE_CONFIG.test(kv)) return { i, bad: true };
      i += w === '-c' ? 2 : 1;
    } else if (GLOBAL_WITH_VALUE.has(w)) i += 2;
    else if (
      /^--(git-dir|work-tree|namespace|super-prefix|exec-path|attr-source)=/.test(
        w,
      ) ||
      GLOBAL_FLAGS.has(w)
    )
      i++;
    else if (/^-C./.test(w)) i++;
    else if (w.startsWith('-'))
      return { i, bad: true }; // includes --config-env and --config
    else break;
  }
  return { i, bad: false };
}

/** Subcommands whose arguments are text or names, never a command line. */
const DATA_SUBS = new Set(
  'commit tag notes log show blame status add describe shortlog diff format-patch merge stash mv rm restore checkout switch cherry-pick revert'.split(
    ' ',
  ),
);

/**
 * Index in `seg` from which words are data (a commit message that says "git push -f" is not a
 * push). Infinity when the segment has no git word followed by such a subcommand.
 */
export function gitDataStart(seg: string[]): number {
  for (let idx = 0; idx < seg.length; idx++) {
    const g = gitWord(seg[idx]!);
    if (!g) continue;
    if (g.sub) return DATA_SUBS.has(g.sub) ? idx + 1 : Infinity;
    const rest = seg.slice(idx);
    const { i, bad } = splitGlobal(rest);
    const sub = rest[i]?.toLowerCase();
    return !bad && sub && DATA_SUBS.has(sub) ? idx + i + 1 : Infinity;
  }
  return Infinity;
}

/** Whether a word names git (any path, case, extension, or `git-<sub>`). */
export function isGitWord(word: string): boolean {
  return gitWord(word) !== null;
}

function gitKinds(words: string[]): K[] {
  const { i, bad } = splitGlobal(words);
  if (bad) return ['ambiguous'];
  const sub = words[i]?.toLowerCase();
  const args = words.slice(i + 1);
  if (sub === undefined) return [];
  if (
    sub === 'filter-branch' ||
    sub === 'filter-repo' ||
    sub === 'update-ref' ||
    sub === 'prune'
  )
    return ['history-rewrite'];
  // Deletes unreachable commits and reflog entries for good.
  if (sub === 'reflog')
    return args.some((a) => a === 'expire' || a === 'delete')
      ? ['history-rewrite']
      : [];
  if (sub === 'gc')
    return args.some((a) => /^--pru[a-z]*(=|$)/.test(a))
      ? ['history-rewrite']
      : [];
  if (sub === 'push') return pushKinds(args);
  if (sub === 'branch') {
    const { kinds, flags, pos } = parseOpts(args, BRANCH);
    const del = flags.has('D') || flags.has('delete') || flags.has('d');
    const force = flags.has('f') || flags.has('force');
    if (flags.has('D') || (del && force)) kinds.add('branch-delete');
    // Moving, renaming over or copying over the default branch rewrites it.
    const moves = force || flags.has('M') || flags.has('C');
    if (
      moves &&
      pos.some((n) =>
        DEFAULT_BRANCHES.has(n.toLowerCase().replace(/^refs\/heads\//, '')),
      )
    )
      kinds.add('history-rewrite');
    return [...kinds];
  }
  if (sub === 'reset') return [...parseOpts(args, RESET).kinds];
  if (sub === 'rebase') {
    const { kinds, flags } = parseOpts(args, REBASE);
    if (flags.has('i')) kinds.add('history-rewrite');
    return [...kinds];
  }
  if (sub === 'config' && args.some((a) => /alias\./i.test(a)))
    return ['ambiguous'];
  if (SAFE_SUBCOMMANDS.has(sub)) return [];
  return ['ambiguous']; // a user alias could hide `push -f`
}

/** `git`, `git.exe`, `GIT`, `git-push`, `git-filter-repo.exe`, by any path (either separator). */
const GIT_NAME = /^git(?:-([a-z][a-z-]*))?(?:\.(?:exe|cmd|bat|py|sh))?$/i;
function gitWord(word: string): { sub?: string } | null {
  const base = word.replace(/\\/g, '/').split('/').pop()!;
  const m = GIT_NAME.exec(base);
  return m ? { sub: m[1]?.toLowerCase() } : null;
}

/** Environment assignments that can rewrite git's config from outside the command line. */
const GIT_CONFIG_ENV = /^GIT_CONFIG[A-Z_0-9]*=/i;

/** `segments` are command-separated word lists. Any `git` word in a segment is analysed. */
export function gitAliases(segments: string[][]): string[] {
  const out = new Set<string>();
  for (const seg of segments) {
    seg.forEach((w, idx) => {
      const g = gitWord(w);
      if (!g) return;
      const rest = g.sub
        ? ['git', g.sub, ...seg.slice(idx + 1)]
        : seg.slice(idx);
      const kinds = gitKinds(rest);
      if (seg.slice(0, idx).some((x) => GIT_CONFIG_ENV.test(x)))
        kinds.push('ambiguous');
      for (const k of kinds) out.add(`git-unsafe:${k}`);
    });
  }
  return [...out];
}
