/**
 * Git safety as an allow-list. A command that touches git (or could run it) is "git-safe", and
 * does not ask, only when every part of it is understood:
 *  - it parses with no expansion at all ($, backticks, globs; `~` and `@{u}` are fine),
 *  - nothing is redirected into a `.git` path,
 *  - no GIT_*, *EDITOR, *PAGER, *_COMMAND or *DIFF variable is set anywhere in it,
 *  - every git call is a literal `git` (or `git.exe`) as the first word of a command, with a
 *    subcommand and options from the tables below (an option not in the table asks),
 *  - every other command is a plain data command (grep, echo, ls, ...), or has no mention of git
 *    in its words, or is a shell whose `-c` script is itself git-safe.
 * Anything else that mentions git, gh, hub, refs, push, reflog, filter-branch, ... asks, as does a
 * shell, interpreter or runner with an inline script, and `source`/`.`.
 *
 * Honest ceiling: this catches likely-dangerous git; an agent that is set on it can still reach
 * git through a script or another program. Protect branches on the server; JAIL limits what a
 * tool can reach.
 */
export type Parse = (s: string) => {
  words: string[];
  expands: boolean;
  segments: string[][];
};

/** Longest command we classify; longer ones that touch git ask. */
export const MAX_COMMAND = 2048;

const NAME = '(?:git|gh|hub)(?:\\.exe)?';
/** Whether a piece of text touches git. Linear: no nested quantifiers. */
const MENTION = new RegExp(
  `(?:^|[\\s/\\\\"'=:;|&(])${NAME}(?:$|[\\s"';|&)])` + // git as a word or path end
    `|(?:^|[\\s/\\\\])git-[a-z][a-z-]*(?:$|[\\s"';|&])` + // git-push style names
    `|(?:^|[\\s/"'>])\\.git(?:$|[\\s/"'])` + // the .git folder
    '|\\b(?:update-ref|reflog|filter-branch|filter-repo)\\b|\\brefs/|\\bheads/|\\bpush\\b' +
    '|reset\\s+--hard|\\bGIT_[A-Z_]+|\\w*EDITOR\\w*=|\\w*PAGER\\w*=|\\w+_COMMAND=|\\w*DIFF\\w*=',
  'i',
);
const DANGEROUS_ENV =
  /^(?:GIT_\w*|\w*EDITOR\w*|\w*PAGER\w*|\w*_COMMAND|\w*DIFF\w*|\w*SSH\w*|LD_\w*|DYLD_\w*|PATH|SHELL|HOME|XDG_\w*|BASH_ENV|ENV|PYTHON\w*|NODE_OPTIONS|PERL5?\w*|RUBY\w*)$/i;
const ASSIGN = /^([A-Za-z_][A-Za-z0-9_]*)=/;
const DOT_GIT_REDIRECT = />>?\s*["']?[^\s;|&]*\.git(?:[/"'\s]|$)/;

const SHELLS = new Set('sh bash zsh dash ash ksh mksh'.split(' '));
/** Programs that run a script, another program, or a string. */
const RUNNERS = new Set(
  (
    'fish csh tcsh pwsh powershell cmd eval exec env sudo doas su nohup timeout nice time command builtin ' +
    'xargs parallel find fd watch flock ssh tmux screen npx pnpx bunx python python2 python3 pypy node nodejs ' +
    'deno bun perl ruby php lua tclsh awk gawk mawk nawk busybox osascript expect script setsid ionice chroot ' +
    'runuser stdbuf unbuffer entr at batch'
  ).split(' '),
);
/** Commands whose arguments are text or file names to read, never a command line. */
const DATA = new Set(
  'grep egrep fgrep rg ag ack echo printf cat ls head tail wc pwd true false stat file which whereis type date uniq tr cut cmp diff'.split(
    ' ',
  ),
);
const INLINE_FLAG =
  /^(?:-[a-zA-Z]{0,2}[ceEpxrRs]|--(?:eval|exec|command|print|execute)|-(?:command|encodedcommand|enc|ec|exec|execdir|ok|okdir)|\/[ck])$/i;
const PLAIN_ARG = /^[A-Za-z0-9_./:=+@%,~-]+$/;
const LITERAL = /^[A-Za-z0-9][A-Za-z0-9._/@~^-]*$/;
const REMOTE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const DEFAULT_BRANCHES = new Set(['main', 'master', 'trunk']);

function base(word: string): string {
  return word
    .replace(/\\/g, '/')
    .split('/')
    .pop()!
    .toLowerCase()
    .replace(/\.(exe|cmd|bat)$/, '');
}

/** The set of options one git subcommand may use. Anything else asks. */
interface Sub {
  long?: string[]; // flags without a value
  eq?: string[]; // --name=value
  short?: string; // letters
  value?: string; // short letters that take a value (the rest of the bundle, or the next word)
  longValue?: string[]; // --name <value> as the next word
  digits?: boolean; // -5
  pos?: (p: string[], seen: Set<string>) => boolean;
}

const READ_LONG = (
  'oneline graph decorate no-decorate stat shortstat numstat name-only name-status patch no-patch ' +
  'abbrev-commit all branches tags remotes follow merges no-merges first-parent reverse color no-color ' +
  'summary cc relative topo-order date-order left-right cherry-pick boundary full-history ' +
  'simplify-by-decoration ancestry-path staged cached no-renames find-renames minimal patience histogram ' +
  'word-diff color-words check quiet verbose short long porcelain branch ignored untracked-files ' +
  'ahead-behind no-ahead-behind always dirty exact-match contains abbrev deleted modified others ' +
  'exclude-standard stage full-name show-toplevel git-dir abbrev-ref verify is-inside-work-tree ' +
  'show-prefix symbolic-full-name heads no-index text ignore-all-space ignore-space-change line-number ' +
  'count files-with-matches files-without-match ignore-case fixed-strings extended-regexp perl-regexp ' +
  'word-regexp invert-match null heading break show-function function-context and or not all-match ' +
  'only-matching name-rev tree pretty-print type size batch-check stdin parents children no-walk ' +
  'show-signature no-abbrev-commit author-date-order exclude-promisor-objects count-only mailmap ' +
  'no-mailmap no-pager'
).split(' ');
const READ_EQ = (
  'date since until after before author committer grep format pretty max-count skip diff-filter abbrev ' +
  'unified color since-as-filter glob branches tags remotes sort contains no-contains merged no-merged ' +
  'points-at match candidates stat word-diff-regex diff-algorithm submodule find-renames find-copies ' +
  'relative inter-hunk-context src-prefix dst-prefix default pretty'
).split(' ');
// Every letter and digit except -O (it names an orderfile for diff and a pager command for grep).
const READ_SHORT =
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ0123456789';
const read = (extra: Partial<Sub> = {}): Sub => ({
  long: READ_LONG,
  eq: READ_EQ,
  short: READ_SHORT,
  digits: true,
  ...extra,
});

const names = (p: string[]) =>
  p.every((x) => LITERAL.test(x) && !x.startsWith('-'));
const remoteAndRef = (p: string[]) =>
  p.length <= 3 &&
  p.every((x) => REMOTE.test(x) || LITERAL.test(x)) &&
  p.every((x) => !/[:+*]/.test(x));

const SUBS: Record<string, Sub> = {
  status: read(),
  diff: read(),
  log: read(),
  show: read(),
  shortlog: read(),
  blame: read(),
  describe: read(),
  'ls-files': read(),
  'ls-tree': read(),
  'rev-parse': read(),
  'rev-list': read(),
  'name-rev': read(),
  'show-ref': read(),
  'cat-file': read(),
  'merge-base': read(),
  'diff-tree': read(),
  'for-each-ref': read(),
  grep: read(),
  version: read(),
  help: read(),
  reflog: read({
    pos: (p) => p.length === 0 || p[0] === 'show' || p[0] === 'exists',
  }),
  add: {
    long: 'all update dry-run verbose patch intent-to-add no-all ignore-errors renormalize force refresh sparse'.split(
      ' ',
    ),
    short: 'AuNnvpfe'.replace('e', ''),
  },
  commit: {
    long: 'all signoff quiet verbose no-verify allow-empty allow-empty-message'.split(
      ' ',
    ),
    eq: ['message', 'author', 'date'],
    short: 'asqvnm',
    value: 'm',
  },
  pull: {
    long: 'ff-only rebase no-rebase ff no-ff quiet verbose autostash no-autostash no-edit prune tags no-tags all commit no-commit stat no-stat squash'.split(
      ' ',
    ),
    eq: ['rebase', 'depth', 'jobs'],
    short: 'qv',
    pos: remoteAndRef,
  },
  fetch: {
    long: 'all prune quiet verbose tags no-tags dry-run unshallow prune-tags multiple'.split(
      ' ',
    ),
    eq: ['depth', 'jobs'],
    short: 'pqvt',
    pos: remoteAndRef,
  },
  checkout: {
    long: 'track no-track detach quiet progress no-progress'.split(' '),
    short: 'bqt',
    value: 'b',
  },
  switch: {
    long: 'track no-track detach quiet'.split(' '),
    short: 'cdqt',
    value: 'c',
    longValue: ['create'],
  },
  stash: {
    long: 'include-untracked keep-index quiet patch all'.split(' '),
    eq: ['message'],
    short: 'mukaqp',
    value: 'm',
    pos: (p) =>
      p.length === 0 ||
      ['push', 'save', 'list', 'show', 'pop', 'apply', 'create'].includes(
        p[0]!,
      ),
  },
  branch: {
    long: 'list all remotes verbose show-current track no-track color no-color column no-column ignore-case'.split(
      ' ',
    ),
    eq: [
      'merged',
      'no-merged',
      'contains',
      'no-contains',
      'sort',
      'format',
      'points-at',
      'abbrev',
    ],
    short: 'arvlt',
    pos: (p) => p.length <= 2 && names(p),
  },
  tag: {
    long: 'list annotate no-contains contains'.split(' '),
    eq: [
      'sort',
      'format',
      'contains',
      'merged',
      'no-merged',
      'points-at',
      'message',
    ],
    short: 'alnm',
    value: 'm',
    digits: true,
    pos: (p) => p.length <= 2 && names(p),
  },
  remote: {
    long: ['verbose'],
    short: 'v',
    pos: (p) =>
      p.length === 0 ||
      ((p[0] === 'show' || p[0] === 'get-url') && p.length <= 2),
  },
  config: {
    long: 'get get-all get-regexp list show-origin show-scope name-only local global system worktree null'.split(
      ' ',
    ),
    short: 'lz',
    pos: (p) => p.length <= 1 && p.every((k) => !/^alias\./i.test(k)),
  },
  merge: {
    long: 'no-ff ff-only ff no-edit squash quiet verbose no-commit commit abort continue autostash no-verify'.split(
      ' ',
    ),
    short: 'qvm',
    value: 'm',
    eq: ['message'],
    pos: names,
  },
  restore: {
    long: 'staged worktree quiet patch'.split(' '),
    eq: ['source'],
    short: 'SWpqs',
    value: 's',
  },
  rm: {
    long: 'cached recursive dry-run quiet ignore-unmatch'.split(' '),
    short: 'rnq',
  },
  mv: { short: 'nvk', long: ['dry-run', 'verbose'] },
  'cherry-pick': {
    long: 'no-commit continue abort skip quit no-edit signoff'.split(' '),
    short: 'xn',
  },
  revert: {
    long: 'no-edit no-commit continue abort skip quit'.split(' '),
    short: 'nm',
    value: 'm',
  },
  clone: {
    long: 'quiet single-branch no-tags recurse-submodules shallow-submodules branch'.split(
      ' ',
    ),
    eq: ['depth', 'branch'],
    short: 'qb',
    value: 'b',
    longValue: ['branch'],
  },
  init: { long: ['quiet', 'bare'], short: 'q' },
  push: {}, // handled by pushSafe
};

/** `git push [-u] <remote> <branch>`: nothing else is provably not a force or a default-branch push. */
function pushSafe(args: string[]): boolean {
  const ok = new Set([
    '-u',
    '--set-upstream',
    '-q',
    '--quiet',
    '-v',
    '--verbose',
    '--dry-run',
    '-n',
    '--no-verify',
    '--progress',
  ]);
  const pos: string[] = [];
  for (const a of args) {
    if (a.startsWith('-')) {
      if (!ok.has(a)) return false;
    } else pos.push(a);
  }
  if (pos.length !== 2 || !REMOTE.test(pos[0]!)) return false;
  let b = pos[1]!.toLowerCase();
  if (!/^[a-z0-9][a-z0-9._/-]*$/.test(b)) return false;
  while (/^(refs\/|heads\/)/.test(b)) b = b.replace(/^(refs\/|heads\/)/, '');
  return (
    !DEFAULT_BRANCHES.has(b) && b !== 'head' && b !== '' && !b.endsWith('/')
  );
}

const SAFE_CONFIG = /^(?:user\.(?:name|email)|color\.[a-z.]+|advice\.[a-z]+)=/i;

/** Whether one literal git invocation (words[0] is git) is in the tables. */
function gitSafe(words: string[]): boolean {
  let i = 1;
  while (i < words.length) {
    const w = words[i]!;
    if (w === '-C') {
      if (!words[i + 1] || !PLAIN_ARG.test(words[i + 1]!)) return false;
      i += 2;
    } else if (w === '-c') {
      if (!SAFE_CONFIG.test(words[i + 1] ?? '')) return false;
      i += 2;
    } else if (
      w === '--no-pager' ||
      w === '-P' ||
      w === '--version' ||
      w === '--help'
    )
      i++;
    else if (w.startsWith('-')) return false;
    else break;
  }
  const sub = words[i]?.toLowerCase();
  if (sub === undefined) return true; // `git` alone, or `git --version`
  const args = words.slice(i + 1);
  if (sub === 'push') return pushSafe(args);
  const t = SUBS[sub];
  if (!t) return false;
  const pos: string[] = [];
  const seen = new Set<string>();
  for (let k = 0; k < args.length; k++) {
    const a = args[k]!;
    if (a === '--') {
      pos.push(...args.slice(k + 1));
      break;
    }
    if (a.startsWith('--')) {
      const name = a.slice(2).split('=')[0]!;
      const hasEq = a.includes('=');
      if (!hasEq && t.long?.includes(name)) seen.add(name);
      else if (hasEq && (t.eq?.includes(name) || t.long?.includes(name)))
        seen.add(name);
      else if (!hasEq && t.longValue?.includes(name)) {
        k++;
        seen.add(name);
      } else return false;
    } else if (a.startsWith('-') && a.length > 1) {
      const bundle = a.slice(1);
      if (t.digits && /^[0-9]+$/.test(bundle)) continue;
      for (let c = 0; c < bundle.length; c++) {
        const ch = bundle[c]!;
        if (!t.short?.includes(ch) && !(t.digits && /[0-9]/.test(ch)))
          return false;
        seen.add(ch);
        if (t.value?.includes(ch)) {
          if (c === bundle.length - 1) k++; // the next word is its value
          break; // the rest of the bundle is its value
        }
      }
    } else pos.push(a);
  }
  return t.pos ? t.pos(pos, seen) : true;
}

function segmentMentions(seg: string[]): boolean {
  return MENTION.test(seg.join(' '));
}

/** `activate` scripts of virtual environments are the one `source` we let through. */
function benignSource(seg: string[], i: number): boolean {
  const target = seg[i + 1];
  return (
    seg.length === i + 2 &&
    target !== undefined &&
    /(^|\/)activate(\.sh)?$/.test(target)
  );
}

function verdict(
  raw: string,
  p: ReturnType<Parse>,
  parse: Parse,
  depth: number,
): boolean {
  if (p.expands || DOT_GIT_REDIRECT.test(raw)) return false;
  for (const w of p.words) {
    const m = ASSIGN.exec(w);
    if (m && DANGEROUS_ENV.test(m[1]!)) return false;
  }
  return p.segments.every((seg) => segmentSafe(seg, parse, depth));
}

function segmentSafe(seg: string[], parse: Parse, depth: number): boolean {
  let i = 0;
  while (i < seg.length && ASSIGN.test(seg[i]!)) i++;
  if (i === seg.length) return true;
  const b = base(seg[i]!);
  if (b === 'git') return gitSafe(seg.slice(i));
  if (DATA.has(b)) return true;
  if (b === 'source' || b === '.') return benignSource(seg, i);
  const args = seg.slice(i + 1);
  if (SHELLS.has(b)) {
    const c = args.findIndex((a) => /^-[a-z]*c[a-z]*$/i.test(a));
    if (c >= 0) {
      const script = args[c + 1];
      if (script === undefined || depth >= 3 || args.length > c + 2)
        return false;
      return verdict(script, parse(script), parse, depth + 1);
    }
    if (args.length === 0) return false; // reads a script from stdin
    return args.every((a) => PLAIN_ARG.test(a)) && !segmentMentions(seg);
  }
  if (RUNNERS.has(b)) {
    if (args.length === 0 && b !== 'env') return false;
    if (args.some((a) => !PLAIN_ARG.test(a) || INLINE_FLAG.test(a)))
      return false;
    return !segmentMentions(seg);
  }
  return !segmentMentions(seg);
}

/** True if the command should be judged at all: it mentions git, or runs something that might. */
function relevant(raw: string, p: ReturnType<Parse>): boolean {
  if (MENTION.test(raw) || MENTION.test(p.words.join(' '))) return true;
  return p.segments.some((seg) => {
    let i = 0;
    while (i < seg.length && ASSIGN.test(seg[i]!)) i++;
    const b = seg[i] === undefined ? '' : base(seg[i]!);
    return SHELLS.has(b) || RUNNERS.has(b) || b === 'source' || b === '.';
  });
}

/**
 * The `git-unsafe:*` aliases for a command. `labels` supplies the danger categories (force-push,
 * push-default-branch, ...) from the deny-list reading, used only to word the prompt: when the
 * command is not provably git-safe and no category fits, the answer is `ambiguous`.
 */
export function gitAliasesFor(
  raw: string,
  parse: Parse,
  labels: (p: ReturnType<Parse>) => string[],
): string[] {
  const p = parse(raw);
  if (!relevant(raw, p)) return [];
  if (raw.length > MAX_COMMAND) return ['git-unsafe:ambiguous'];
  if (verdict(raw, p, parse, 0)) return [];
  const cats = labels(p);
  return cats.length ? cats : ['git-unsafe:ambiguous'];
}
