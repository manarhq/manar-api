import { describe, expect, it } from 'vitest';
import { learningMayAllow, learningWindow } from './learning';

const NOW = new Date('2026-11-05T12:00:00Z');
const day = (n: number) => new Date(NOW.getTime() - n * 86_400_000);
const host = (over = {}) => ({
  approvedAt: day(2),
  learningStartedAt: null,
  learningOff: false,
  ...over,
});

describe('learning window', () => {
  it('runs 7 days from approval', () => {
    expect(learningWindow(host(), 7, NOW).active).toBe(true);
    expect(learningWindow(host({ approvedAt: day(8) }), 7, NOW).active).toBe(
      false,
    );
  });
  it('an admin restart moves the start, and off or 0 days ends it', () => {
    const h = host({ approvedAt: day(30), learningStartedAt: day(1) });
    expect(learningWindow(h, 7, NOW).active).toBe(true);
    expect(learningWindow(host({ learningOff: true }), 7, NOW).active).toBe(
      false,
    );
    expect(learningWindow(host(), 0, NOW).active).toBe(false);
    expect(learningWindow(host({ approvedAt: null }), 7, NOW).active).toBe(
      false,
    );
  });
});

describe('what learning may let through', () => {
  const T = 'host.cursor';
  const ok = (actionId: string, resource: string, riskScore = 35) =>
    learningMayAllow({ toolId: T, actionId, resource, riskScore });
  it('lets an ordinary edit, mcp call or fetch through', () => {
    expect(ok('edit', '/home/sara/proj/src/a.ts')).toBe(true);
    expect(ok('mcp', 'github/create_issue')).toBe(true);
    expect(ok('webfetch', 'https://docs.x.io/a', 20)).toBe(true);
  });
  it('never high risk, secrets, climbs, expansions, risky git or sites', () => {
    expect(ok('shell', 'ls', 70)).toBe(false);
    expect(ok('edit', '/home/sara/proj/.env')).toBe(false);
    expect(ok('read', '/home/sara/.ssh/id_rsa', 10)).toBe(false);
    expect(ok('edit', '../../etc/x')).toBe(false);
    expect(ok('shell', 'ls $(cat x)', 30)).toBe(false);
    expect(ok('shell', 'git push --force', 30)).toBe(false);
    expect(ok('site.connect', 'https://x.io', 10)).toBe(false);
    expect(ok('secret.use', 'db-password', 10)).toBe(false);
  });
});
