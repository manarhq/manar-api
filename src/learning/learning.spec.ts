import { describe, expect, it } from 'vitest';
import { learningCandidate, learningWindow } from './learning';

const NOW = new Date('2026-11-05T12:00:00Z');
const day = (n: number) => new Date(NOW.getTime() - n * 86_400_000);
const host = (over = {}) => ({
  firstApprovedAt: day(2),
  learningStartedAt: null,
  learningOff: false,
  ...over,
});

describe('learning window', () => {
  it('runs 7 days from the FIRST approval', () => {
    expect(learningWindow(host(), 7, NOW).active).toBe(true);
    expect(
      learningWindow(host({ firstApprovedAt: day(8) }), 7, NOW).active,
    ).toBe(false);
  });
  it('an admin restart moves the start, and off, 0 days or no first approval end it', () => {
    const h = host({ firstApprovedAt: day(30), learningStartedAt: day(1) });
    expect(learningWindow(h, 7, NOW).active).toBe(true);
    expect(learningWindow(host({ learningOff: true }), 7, NOW).active).toBe(
      false,
    );
    expect(learningWindow(host(), 0, NOW).active).toBe(false);
    expect(learningWindow(host({ firstApprovedAt: null }), 7, NOW).active).toBe(
      false,
    );
  });
});

describe('what learning may quiet', () => {
  const T = 'host.cursor';
  const c = (actionId: string, resource: string, riskScore = 35) =>
    learningCandidate({ toolId: T, actionId, resource, riskScore });

  it('a file in a home project folder, a read-only command; never an mcp call', () => {
    expect(c('edit', '/home/sara/proj/src/a.ts')).toEqual({
      scope: '/home/sara/proj/src/*',
      needsSeenSite: false,
    });
    // An MCP call can do anything: never quiet, whatever the server and tool are called.
    for (const t of ['github/create_issue', 'github/delete_repository'])
      expect(c('mcp', t)).toBeNull();
    expect(c('shell', 'ls -la src', 30)).toEqual({
      scope: null,
      needsSeenSite: false,
    });
  });
  it('a web fetch qualifies only once the site has been seen', () => {
    expect(c('webfetch', 'https://docs.x.io/a', 20)).toEqual({
      scope: 'https://docs.x.io/*',
      needsSeenSite: true,
    });
    expect(c('webfetch', 'http://docs.x.io/a', 20)).toBeNull();
    expect(c('webfetch', 'https://good.com@evil.com/', 20)).toBeNull();
  });
  it.each([
    ['no scope: outside any home project folder', 'edit', '/etc/hosts'],
    [
      'no scope: a top-level file in the home folder',
      'edit',
      '/home/sara/notes.txt',
    ],
    ['no scope: a relative path', 'edit', 'src/a.ts'],
    ['no scope: a project outside a home', 'write', '/work/app/a.ts'],
    [
      'dot folder: .git hooks',
      'write',
      '/home/sara/proj/.git/hooks/pre-commit',
    ],
    ['dot folder: .vscode', 'edit', '/home/sara/proj/.vscode/tasks.json'],
    ['dot folder: .claude', 'edit', '/home/sara/proj/.claude/settings.json'],
    ['dot folder at depth', 'edit', '/home/sara/proj/src/a/.cache/x.ts'],
    ['bin folder', 'write', '/home/sara/proj/bin/run.sh'],
    [
      'PowerShell profile',
      'write',
      'C:\\Users\\sara\\Documents\\WindowsPowerShell\\profile.ps1',
    ],
    [
      'startup folder',
      'write',
      'C:\\Users\\sara\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\a.cmd',
    ],
    ['secret', 'edit', '/home/sara/proj/.env'],
    ['secret read', 'read', '/home/sara/.ssh/id_rsa'],
    ['a climb', 'edit', '/home/sara/proj/../omar/a.ts'],
    ['secret handover', 'secret.use', 'db-password'],
    ['a new site', 'site.connect', 'https://x.io'],
  ])('keeps asking: %s', (_n, action, resource) => {
    expect(c(action, resource)).toBeNull();
  });
  it('never a command that is not clearly read-only, or anything high risk', () => {
    for (const cmd of [
      'pnpm test',
      'npm run build',
      'cargo test',
      'go test ./...',
      'pytest',
      'make test',
      'git status',
      'git push --force',
      'rm -rf x',
      'ls $(cat x)',
      'curl https://x.io',
      'cat .env',
      'grep -r password',
    ])
      expect(c('shell', cmd, 30), cmd).toBeNull();
    expect(c('shell', 'ls src', 70)).toBeNull(); // the catalogue score is not lowered
    expect(c('edit', '/home/sara/proj/a.ts', 50)).toBeNull();
  });
});
