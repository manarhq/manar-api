import { describe, expect, it } from 'vitest';
import { resourceAliases, shellWords } from './resource-aliases';

/** What the Balanced preset asks about: a git rule or the "shell would expand it" rule. */
const asks = (cmd: string) =>
  resourceAliases(cmd, 'command').some(
    (a) => a.startsWith('git-unsafe:') || a.startsWith('unsafe-command:'),
  );
const gitAsks = (cmd: string) =>
  resourceAliases(cmd, 'command').some((a) => a.startsWith('git-unsafe:'));

describe('git allow-list: every bypass found by review asks', () => {
  const MUST_ASK = [
    // options that swallow the remote, abbreviations, bundles
    'git push -oq origin main',
    'git push -ofoo origin +main',
    'git push --forc origin x',
    'git push -uf origin x',
    'git push --mirror',
    'git push origin :feature',
    'git push origin +feature',
    'git push origin HEAD',
    'git push origin feature:main',
    'git push',
    'git push origin',
    'git push --delete origin feature',
    'git push --all',
    // config and environment that can run or rewrite things
    'export GIT_CONFIG_COUNT=1; git push origin feature',
    'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.p GIT_CONFIG_VALUE_0="push -f" git p',
    'GIT_SSH_COMMAND="sh -c x" git fetch origin',
    'GIT_EDITOR="git push -f" git commit',
    'GIT_EXTERNAL_DIFF=./x git diff',
    'GIT_SEQUENCE_EDITOR=./x git rebase -i HEAD~2',
    'EDITOR=./x git commit',
    'PAGER=./x git log',
    'echo "[alias]" >> .git/config; git status',
    'printf x > .git/hooks/pre-push',
    'cp x .git/config',
    // commands that run git or call it indirectly
    'git fetch --upload-pack="sh x" origin',
    'git ls-remote --upload-pack="sh x" origin',
    'git difftool --extcmd="sh x"',
    'git grep -O"sh x" foo',
    'git grep --open-files-in-pager=x foo',
    'git submodule foreach "git push -f"',
    'git bisect run ./x',
    'git rebase --exec "x" main',
    'git -c core.sshCommand=x fetch',
    'git -c alias.p="push -f" p',
    'git --exec-path=/tmp/x status',
    'git log --output=.git/config',
    'git diff --output=x',
    // renamed or wrapped binaries
    'hash -p /usr/bin/git g; g push -f',
    'ln -s /usr/bin/git /tmp/g && /tmp/g push -f',
    'cp /usr/bin/git /tmp/x; /tmp/x push -f',
    'install /usr/bin/git /tmp/g',
    'exec "$0" push origin +main git',
    'x=gi; ${x}t push -f',
    'gi[t] push -f',
    "sh -c 'gi[t] push -f'",
    'g""it push origin +main',
    "'g'it push -f",
    '\\git push -f',
    'command git push -f',
    'sudo git push -f',
    'env git push -f',
    'env -S"git push -f"',
    'nice git push -f',
    'xargs git push -f',
    'printf %s -f | xargs git push origin feature',
    'parallel git push ::: x',
    'find . -exec git push -f +',
    'time git push -f',
    'git-push --force',
    'git-reset --hard',
    '/usr/bin/git-push -f',
    // shells, runners and interpreters with an inline script
    "sh -c 'git push -f'",
    'bash -c \'git push origin feature "$1"\' _ -f',
    "ash -c 'git push -f'",
    "mksh -c 'git push -f'",
    "dash -c 'git push -f'",
    "zsh -c 'git push -f'",
    "fish -c 'git push -f'",
    "flock /tmp/l -c 'git push -f'",
    "watch -n1 'git push -f'",
    'watch git push -f',
    "ssh host 'git push -f'",
    'ssh host git push -f',
    "tmux new 'git push -f'",
    'tmux new-session -d git push -f',
    "npx -c 'git push -f'",
    "eval 'git push -f'",
    "eval 'X=main; git push origin feature:$X'",
    'python -c \'import os; os.system("git push -f")\'',
    "python3 -c 'print(1)'",
    'node -e \'require("child_process").execSync("git push -f")\'',
    'perl -e \'system("git push -f")\'',
    'ruby -e \'system("git push -f")\'',
    "pwsh -c '&(gcm g?t) push -f'",
    "pwsh -c \"'{0}it' -f 'g' | iex\"",
    'powershell -EncodedCommand ZwBpAHQA',
    'cmd /c g^it push -f',
    "echo 'git push -f' | sh",
    "echo 'git push -f' | bash",
    'source ./push.sh',
    '. ./push.sh',
    'bash ./x.sh git',
    // gh, hub and ref plumbing
    'gh api -X DELETE repos/o/r/git/refs/heads/main',
    'gh repo sync --force',
    'hub push -f',
    'git update-ref -d refs/heads/main',
    'git reflog expire --expire=now --all',
    'git gc --prune=now',
    'git filter-branch --tree-filter x',
    'git filter-repo --path x',
    'git reset --hard origin/main',
    'git rebase -i HEAD~3',
    'git rebase main',
    'git branch -D x',
    'git branch -f main HEAD~3',
    'git branch -M main',
    'git switch -C main',
    'git checkout -B main',
    'git checkout --orphan x',
    'git fetch . +x:main',
    'git fetch origin x:main',
    'git pull origin x:main',
    'git stash clear',
    'git stash drop',
    'git tag -d v1',
    'git tag -f v1',
    'git remote add x y',
    'git remote set-url origin y',
    'git config alias.p "push -f"',
    'git config user.name x',
    'git commit --amend',
    'git commit --amend -m x',
    'git clean -fdx',
    'git gc',
    'git merge --exec x',
    'git merge -s ours feature',
    'git merge -X theirs feature',
    'git merge --strategy=ours feature',
    'git merge -Xours feature',
  ];
  it.each(MUST_ASK)('%s', (cmd) => {
    expect(asks(cmd)).toBe(true);
  });
});

describe('git allow-list: everyday commands do not ask', () => {
  const MUST_NOT_ASK = [
    'git status',
    'git status --short --branch',
    'git diff',
    'git diff --stat HEAD~1',
    'git diff -- src/policy/git-safety.ts',
    'git log',
    'git log --oneline -5',
    'git log --oneline --graph --decorate --all',
    'git log @{u}..',
    'git log HEAD@{1}',
    'git log --format=%H',
    'git log --pretty=format:"%h %an %s" -5',
    'git log --grep="git push -f"',
    'git show HEAD',
    'git show HEAD:README.md',
    'git blame src/a.ts',
    'git add .',
    'git add -A',
    'git add src/policy/git-safety.ts',
    'git commit -m "fix"',
    'git commit -am "fix"',
    'git commit -m "stop git push -f from main"',
    "git commit -m 'git reset --hard is scary'",
    'git commit -s -m "x"',
    'git pull',
    'git pull --ff-only',
    'git pull --rebase origin main',
    'git fetch',
    'git fetch --all --prune',
    'git fetch origin',
    'git checkout feature',
    'git checkout -b feature',
    'git switch feature',
    'git switch -c feature',
    'git merge feature',
    'git merge --no-ff feature',
    'git merge --ff-only origin/main',
    'git stash',
    'git stash push -m wip',
    'git stash pop',
    'git stash list',
    'git branch',
    'git branch -a',
    'git branch feature',
    'git tag',
    'git tag v1.0.0',
    'git tag -a v1 -m "release"',
    'git remote -v',
    'git rev-parse HEAD',
    'git rev-parse --show-toplevel',
    'git ls-files',
    'git describe --tags',
    'git config --get user.name',
    'git config --list',
    'git config user.email',
    'git reflog',
    'git push origin feature',
    'git push -u origin feature/x',
    'git -C /repo status',
    'git --no-pager log',
    'git --version',
    'git -c user.name=x commit -m y',
    'CI=1 git status',
    'cd repo && git status && git diff',
    "sh -c 'git status'",
    'git status; git diff; git log -3',
    'git status | head',
    // not git at all, or git only as data
    'npm test',
    'pnpm lint',
    'ls',
    'ls -la src',
    'ls src/policy/git-safety.ts',
    'cat src/policy/git-safety.ts',
    'grep "git push" docs/x.md',
    "grep -rn 'git push -f' .",
    'rg "git reset --hard" src',
    'echo "git push -f"',
    'echo hello > out.txt',
    'cat .git/config',
    'ls .git',
    'cargo build',
    'go test ./...'.replace('./...', 'ok'),
    'make build',
    'python script.py',
    'node app.js',
    'bash run.sh',
    'source .venv/bin/activate',
    'cd src && ls',
  ];
  it.each(MUST_NOT_ASK)('%s', (cmd) => {
    expect(gitAsks(cmd), cmd).toBe(false);
  });
});

describe('git allow-list: bounds and speed', () => {
  it('asks about a git command longer than the 2048 character cap', () => {
    expect(gitAsks('git status ' + 'a '.repeat(1100))).toBe(true);
  });
  it('classifies a long command in linear time', () => {
    const cmd = 'git log ' + '--oneline '.repeat(200);
    const t = Date.now();
    for (let i = 0; i < 50; i++) resourceAliases(cmd + i, 'command');
    expect(Date.now() - t).toBeLessThan(1000);
  });
  it('treats @{u} as git syntax and a real brace expansion as an expansion', () => {
    expect(shellWords('git log @{u}..').expands).toBe(false);
    expect(shellWords('echo {a,b}').expands).toBe(true);
    expect(shellWords('echo {1..3}').expands).toBe(true);
  });
  it('answers from the same list on a second call', () => {
    const a = resourceAliases('git push -f', 'command');
    expect(resourceAliases('git push -f', 'command')).toBe(a);
  });
});

describe('relevance covers every git name the parser accepts', () => {
  it.each([
    'git.cmd push -f origin HEAD:main',
    'git.bat push -f origin HEAD:main',
    'C:\\Git\\cmd\\git.cmd push --force origin main',
    './git-push.sh -f origin main',
    'git-push.py origin +main',
    '/opt/git/bin/GIT.EXE push -f origin main',
  ])('%s asks', (cmd) => {
    expect(gitAsks(cmd)).toBe(true);
  });
});
