import { describe, expect, it } from 'vitest';
import {
  resourceAliases,
  resourceKindFor,
  shellWords,
} from './resource-aliases';

const secret = (r: string, kind: 'path' | 'command' = 'path') =>
  resourceAliases(r, kind).some((a) => a.startsWith('secret-file:'));

describe('resourceAliases', () => {
  it('finds secrets whatever the whitespace in a file path', () => {
    expect(secret('/home/u/my keys/.aws/credentials')).toBe(true);
    expect(secret('/home/u/.aws/credentials ')).toBe(true);
    expect(secret('/work/my shop/.env')).toBe(true);
    expect(secret('C:\\Users\\Sam Lee\\.ssh\\id_rsa')).toBe(true);
  });
  it('sees through //, /./ and .. variants', () => {
    expect(secret('/home/u//.ssh///id_rsa')).toBe(true);
    expect(secret('/home/u/./.ssh/./id_rsa')).toBe(true);
    expect(secret('/home/u/proj/../.ssh/id_rsa')).toBe(true);
    expect(secret('~/proj/../.ssh/id_rsa')).toBe(true);
    expect(secret('~//.ssh/id_rsa')).toBe(true);
  });
  it('marks a path that climbs out of its root as unsafe', () => {
    expect(resourceAliases('../../.ssh/id_rsa')).toContain(
      'unsafe-path:traversal',
    );
    expect(resourceAliases('~/../other/x')).toContain('unsafe-path:traversal');
    expect(resourceAliases('~/a/../../../etc/passwd')).toContain(
      'unsafe-path:traversal',
    );
    expect(resourceAliases('/work/shop/src/a.ts')).toEqual([]);
    expect(resourceAliases('~/a/../../../etc/passwd')).toContain(
      'unsafe-path:traversal',
    );
  });
  it('normalises Windows paths', () => {
    expect(resourceAliases('C:\\Users\\x\\.aws\\credentials')).toEqual(
      expect.arrayContaining(['~/.aws/credentials', 'secret-file:credentials']),
    );
    expect(resourceAliases('C:\\Windows\\System32\\x.dll')).toContain(
      'c:/windows/system32/x.dll',
    );
  });
  it('finds secret paths inside commands, and ignores plain words', () => {
    expect(secret('cat ~/.ssh/id_rsa', 'command')).toBe(true);
    expect(secret('cat "/home/u/.aws/credentials"', 'command')).toBe(true);
    expect(secret('cat credentials', 'command')).toBe(true); // run inside ~/.aws
    expect(secret('cat id_ed25519', 'command')).toBe(true);
    expect(secret('grep password src', 'command')).toBe(false);
  });
  it('reads commands like a shell: escapes, quotes, globs and substitution', () => {
    expect(secret('cat ~/.a\\ws/credentials', 'command')).toBe(true);
    expect(secret("cat '/home/u/.aws/credentials'", 'command')).toBe(true);
    expect(resourceAliases('cat ~/.ssh/*', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat $(echo ~/.ssh/id_rsa)', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat `echo x`', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat ~/.ssh/{id_rsa,x}', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases("echo '*' '$HOME'", 'command')).toEqual([]);
    expect(resourceAliases('echo "a b" c', 'command')).toEqual([]);
    expect(shellWords('a "b c" d\\ e;f').words).toEqual([
      'a',
      'b c',
      'd e',
      'f',
    ]);
  });
  it('keeps traversal markers in commands', () => {
    expect(resourceAliases('cat ../../etc/passwd', 'command')).toContain(
      'unsafe-path:traversal',
    );
    expect(resourceAliases('cat ../../.ssh/id_rsa', 'command')).toEqual(
      expect.arrayContaining(['unsafe-path:traversal', 'secret-file:id_rsa']),
    );
  });
  it('fails closed on line continuations, control characters and odd quoting', () => {
    expect(secret('cat ~/.ssh/id_\\\nrsa', 'command')).toBe(true); // continuation vanishes
    expect(resourceAliases('cat a\nb', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat a\rb', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat "a\u0001b"', 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases("cat 'unterminated", 'command')).toContain(
      'unsafe-command:expansion',
    );
    expect(resourceAliases('cat <(echo x)', 'command')).toContain(
      'unsafe-command:expansion',
    );
  });
  it('fails closed on tilde forms the parser does not expand', () => {
    for (const c of [
      'cat ~root/.ssh/id_rsa',
      'cd ~+',
      'cd ~-',
      'X=~/.aws/config',
      'PATH=a:~/b',
    ]) {
      expect(resourceAliases(c, 'command')).toContain(
        'unsafe-command:expansion',
      );
    }
    expect(resourceAliases('cat ~/notes.txt', 'command')).toEqual([]);
    expect(resourceAliases('cd ~', 'command')).toEqual([]);
  });
  it('keeps Windows shell paths (backslashes) and fails closed on their expansions', () => {
    expect(secret('type C:\\Users\\x\\.aws\\credentials', 'command')).toBe(
      true,
    );
    const ps = resourceAliases(
      'Get-Content $env:USERPROFILE\\.ssh\\id_ed25519',
      'command',
    );
    expect(ps).toContain('secret-file:id_ed25519');
    expect(ps).toContain('unsafe-command:expansion');
    const cmd = resourceAliases(
      'type %USERPROFILE%\\.aws\\credentials',
      'command',
    );
    expect(cmd).toContain('secret-file:credentials');
    expect(cmd).toContain('unsafe-command:expansion');
    expect(resourceAliases('dir C:\\work\\shop', 'command')).toEqual([]);
    expect(resourceAliases('dir sub\\dir', 'command')).toContain(
      'unsafe-command:expansion',
    );
  });
  it('resolves Windows drive paths as rooted and flags clamped ..', () => {
    expect(resourceAliases('C:\\Users\\x\\..\\..\\..\\Windows')).toContain(
      'unsafe-path:traversal',
    );
    expect(resourceAliases('c:/Users/x/../y/.aws/credentials')).toEqual(
      expect.arrayContaining(['~/.aws/credentials', 'secret-file:credentials']),
    );
    expect(resourceAliases('/../etc/passwd')).toContain(
      'unsafe-path:traversal',
    );
  });
  it('kind is scoped to the tool; unknown means path', () => {
    expect(resourceKindFor('host.claude-code', 'bash')).toBe('command');
    expect(resourceKindFor('host.claude-code', 'webfetch')).toBe('other');
    expect(resourceKindFor('host.claude-code', 'read')).toBe('path');
    expect(resourceKindFor('host.cursor', 'bash')).toBe('command');
    expect(resourceKindFor('evil.tool', 'bash')).toBe('path');
    expect(resourceKindFor('evil.tool', 'webfetch')).toBe('path');
    expect(resourceKindFor('host.claude-code', 'mystery')).toBe('path');
    expect(resourceKindFor('host.cursor', 'mystery')).toBe('path');
  });
  it('gives URLs and tool names no aliases', () => {
    expect(resourceAliases('https://example.com/.env', 'other')).toEqual([]);
  });
});

describe('git safety aliases', () => {
  const git = (c: string) =>
    resourceAliases(c, 'command').filter((a) => a.startsWith('git-unsafe:'));
  const cases: Array<[string, string]> = [
    ['git push --force origin feat', 'force-push'],
    ['git push -f', 'force-push'],
    ['git push -uf origin feat', 'force-push'],
    ['git push --force-with-lease origin feat', 'force-push'],
    ['git push origin +feat', 'force-push'],
    ['git push origin +HEAD:feat', 'force-push'],
    ['git push origin main', 'push-default-branch'],
    ['git push origin HEAD:refs/heads/master', 'push-default-branch'],
    ['git push --all', 'push-default-branch'],
    ['git push origin :feat', 'branch-delete'],
    ['git push origin --delete feat', 'branch-delete'],
    ['git push -d origin feat', 'branch-delete'],
    ['git branch -D feat', 'branch-delete'],
    ['git branch --delete --force feat', 'branch-delete'],
    ['git reset --hard origin/main', 'history-rewrite'],
    ['git rebase -i HEAD~3', 'history-rewrite'],
    ['git filter-branch --tree-filter x', 'history-rewrite'],
    ['git filter-repo --path x', 'history-rewrite'],
    ['git-filter-repo --path x', 'history-rewrite'],
    ['git -C /repo push -f', 'force-push'],
    ['git -c user.name=x --no-pager push -f', 'force-push'],
    ['git -c core.x=1 push origin feat', 'ambiguous'],
    ['GIT_TERMINAL_PROMPT=0 git push -f', 'force-push'],
    ['env FOO=1 /usr/bin/git push -f', 'force-push'],
    ['cd x && git push -f', 'force-push'],
    ['sh -c "git push -f"', 'force-push'],
    ["bash -lc 'cd r; git push origin main'", 'push-default-branch'],
    ['git push', 'push-default-branch'],
    ['git push origin', 'push-default-branch'],
    ['git push --forc origin x', 'force-push'],
    ['git push --force-with origin x', 'force-push'],
    ['git push --mir', 'force-push'],
    ['git push --del origin x', 'branch-delete'],
    ['git push --al', 'push-default-branch'],
    ['git push -u2f origin x', 'force-push'],
    ['git push -fu origin x', 'force-push'],
    ['git push -x origin feat', 'ambiguous'],
    ['git push --weird origin feat', 'ambiguous'],
    ['git reset --ha HEAD~1', 'history-rewrite'],
    ['git reset --bogus', 'ambiguous'],
    ['git branch --del --for x', 'branch-delete'],
    ['git branch -Dq x', 'branch-delete'],
    ['git rebase --inter main', 'history-rewrite'],
    ['git -c push.default=matching push origin feat', 'ambiguous'],
    ['git -c include.path=/x push origin feat', 'ambiguous'],
    ['git -calias.x=push x', 'ambiguous'],
    ['git --config-env=alias.p=E p', 'ambiguous'],
    ['GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p git p', 'ambiguous'],
    ['GIT_CONFIG_PARAMETERS="alias.p=push -f" git p', 'ambiguous'],
    ['git push origin refs/heads/main', 'push-default-branch'],
    ['git push origin heads/main', 'push-default-branch'],
    ['git push origin refs/heads/heads/main', 'push-default-branch'],
    ['git push origin +refs/heads/MAIN', 'push-default-branch'],
    ['git push origin HEAD', 'push-default-branch'],
    ['git push origin HEAD:refs/heads/main', 'push-default-branch'],
    ['git push origin refs/heads/*:refs/heads/*', 'push-default-branch'],
    ['git push origin feat:main', 'push-default-branch'],
    ['git push --branches', 'push-default-branch'],
    ['git push --mirror', 'push-default-branch'],
    ['git-push --force', 'force-push'],
    ['git-branch -D x', 'branch-delete'],
    ['git-reset --hard', 'history-rewrite'],
    ['git-filter-branch x', 'history-rewrite'],
    ['/usr/bin/git-push -f', 'force-push'],
    ['GIT.EXE push -f', 'force-push'],
    ['"C:\\Program Files\\Git\\cmd\\git.exe" push -f', 'force-push'],
    ['C:\\Git\\git-push.exe --force', 'force-push'],
    ['command git push -f', 'force-push'],
    ['exec git push -f', 'force-push'],
    ['xargs git push -f', 'force-push'],
    ["env -S 'git push -f'", 'force-push'],
    ['sh -c \'g""it push -f\'', 'force-push'],
    ['bash -c "sh -c \'git push -f\'"', 'force-push'],
    ['git p', 'ambiguous'],
    ['git push --recurse-submodules check origin main', 'push-default-branch'],
    ['git-filter-repo.py --path x', 'history-rewrite'],
    ['git-filter-repo.exe --path x', 'history-rewrite'],
    [
      'echo x | python -c \'print(1)\' ; printf "git push -f" | xargs -I{} {}',
      'force-push',
    ],
    ['foo "git push -f"', 'force-push'],
    ['git -c alias.p="push -f" p', 'ambiguous'],
    ['git config alias.p "push -f"', 'ambiguous'],
    ['git --weird push', 'ambiguous'],
  ];
  it.each(cases)('%s -> %s', (cmd, kind) => {
    expect(git(cmd)).toContain(`git-unsafe:${kind}`);
  });
  it.each([
    'git status',
    'git push origin feat/x',
    'git push -u origin feat/x',
    'git -c user.name=x -c color.ui=never push origin feat',
    'git branch feature',
    'git log --oneline | head',
    'echo push -f',
    'git commit -m "push -f main"',
  ])('%s is not flagged', (cmd) => {
    expect(git(cmd)).toEqual([]);
  });
});

describe('git safety: reviewer probes (nested shells, env -S, fan-out, Windows shells)', () => {
  const kinds = (c: string) =>
    resourceAliases(c, 'command').filter((a) => a.startsWith('git-unsafe:'));
  it.each([
    // H1: expansion inside a nested shell or eval
    `sh -c 'git push origin feature "$1"' _ -f`,
    `X=-f sh -c 'git push origin feature $X'`,
    `bash -c 'git push $0 $1' origin +main`,
    `eval 'X=main; git push origin feature:$X'`,
    `pwsh -c '$x="-f"; git push origin feature $x'`,
    `sh -c 'G=git; $G push -f'`,
    `sh -c 'echo $(printf git) push -f'`,
    // H2: env -S attached and long form
    `env -S'git push -f'`,
    `env --split-string='git push -f'`,
    `env -iS'git push origin +main'`,
    // H3: fan-out programs
    `printf %s -f | xargs git push origin feature`,
    `xargs -I{} git push origin {}`,
    `parallel git push origin ::: feature`,
    `find . -name x -exec git push origin feature {} +`,
    // PowerShell and cmd
    `powershell -EncodedCommand ZwBpAHQAIABwAHUAcwBoACAALQBmAA==`,
    `pwsh -enc ZwBp`,
    `pwsh -e ZwBp`,
    `cmd /c g^it push -f`,
    `pwsh -c "& ('g'+'it') push -f"`,
    `powershell -Command "iex 'git push -f'"`,
    `pwsh -c "g\`it push -f"`,
    // history rewriting by other means
    'git reflog expire --expire=now --all',
    'git reflog delete HEAD@{1}',
    'git gc --prune=now',
    'git gc --pru=now',
    'git prune',
    'git branch -f main HEAD~3',
    'git branch -M main',
    'git branch -fC main other',
    'git update-ref -d refs/heads/main',
  ])('%s asks', (cmd) => {
    expect(kinds(cmd).length).toBeGreaterThan(0);
  });

  it.each([
    'git commit -m "fix: stop git push -f from main"',
    "git commit -m 'git reset --hard is scary'",
    'git tag -a v1 -m "git push --force"',
    'git log --grep="git push -f"',
    'git --version',
    'git --help',
    'git log --format=%H',
    'git log --pretty=format:"%h %an %s" -5',
    'git log --format="%H%n%an"',
    "sh -c 'git status'",
    'git reflog',
    'git reflog show',
  ])('%s does not ask', (cmd) => {
    expect(kinds(cmd)).toEqual([]);
    expect(resourceAliases(cmd, 'command')).not.toContain(
      'unsafe-command:expansion',
    );
  });
});
