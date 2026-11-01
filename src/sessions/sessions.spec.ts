import { describe, expect, it } from 'vitest';
import {
  SESSION_GAP_MS,
  groupSessions,
  parseSessionId,
  redactSession,
  type RawEvent,
} from './sessions';

const T0 = Date.parse('2026-11-01T10:00:00Z');
let n = 0;
const act = (
  min: number,
  actionId: string,
  resource: string,
  extra: Record<string, unknown> = {},
): RawEvent => ({
  id: `e${n++}`,
  eventType: 'host.action_decided',
  timestamp: new Date(T0 + min * 60_000),
  data: {
    hostId: 'h1',
    toolId: 'host.cursor',
    actionId,
    resource,
    decision: 'ALLOW',
    ...extra,
  },
});

describe('groupSessions', () => {
  it('groups by the tool session id and keeps steps in time order', () => {
    const s = groupSessions([
      act(5, 'edit', '/home/a/p/x.ts', { sessionId: 'S1' }),
      act(1, 'shell', 'git status', { sessionId: 'S1' }),
      act(2, 'webfetch', 'https://example.com/a?k=1', { sessionId: 'S2' }),
    ]);
    expect(s).toHaveLength(2);
    const s1 = s.find((x) => x.counts.commands === 1)!;
    expect(s1.source).toBe('hook');
    expect(s1.steps.map((x) => x.kind)).toEqual(['command', 'file']);
  });

  it('falls back to a 30-minute gap and says so', () => {
    const s = groupSessions([
      act(0, 'shell', 'ls'),
      act(10, 'read', '/a'),
      act(10 + SESSION_GAP_MS / 60_000 + 1, 'shell', 'pwd'),
    ]);
    expect(s).toHaveLength(2);
    expect(s.every((x) => x.source === 'gap')).toBe(true);
    expect(s.map((x) => x.steps.length).sort()).toEqual([1, 2]);
  });

  it('never mixes devices or tools, and drops events without a device', () => {
    const other = act(1, 'shell', 'ls', { hostId: 'h2' });
    const noHost = act(1, 'shell', 'ls', { hostId: '' });
    const s = groupSessions([act(0, 'shell', 'ls'), other, noHost]);
    expect(s).toHaveLength(2);
    expect(new Set(s.map((x) => x.hostId))).toEqual(new Set(['h1', 'h2']));
  });

  it('puts approvals and secrets into the session they happened in', () => {
    const s = groupSessions([
      act(0, 'shell', 'git push --force', {
        sessionId: 'S1',
        decision: 'APPROVAL_REQUIRED',
        approvalId: 'a1',
      }),
      {
        id: 'ap',
        eventType: 'approval.approved',
        timestamp: new Date(T0 + 60_000),
        data: { approvalRequestId: 'a1', hostId: 'h1', toolId: 'host.cursor' },
      },
      act(2, 'shell', 'ls', { sessionId: 'S1' }),
      {
        id: 'sec',
        eventType: 'secret.touched',
        timestamp: new Date(T0 + 90_000),
        data: {
          hostId: 'h1',
          toolId: 'host.cursor',
          pathClass: 'ssh-key',
          maskedPath: '~/.ssh/id_ed25519',
          blocked: true,
        },
      },
    ]);
    expect(s).toHaveLength(1);
    expect(s[0]!.counts).toMatchObject({
      approvals: 1,
      secrets: 1,
      commands: 2,
      blocked: 1,
    });
    expect(s[0]!.steps.map((x) => x.kind)).toEqual([
      'command',
      'approval',
      'secret',
      'command',
    ]);
    expect(s[0]!.steps[1]!.outcome).toBe('approved');
  });

  it('round-trips the session id and refuses junk', () => {
    const [s] = groupSessions([act(0, 'shell', 'ls', { sessionId: 'S1' })]);
    expect(parseSessionId(s!.id)).toMatchObject({
      hostId: 'h1',
      source: 'hook',
      key: '\nS1',
    });
    expect(parseSessionId('nope')).toBeNull();
    expect(
      parseSessionId(Buffer.from('[1,2,3,4]').toString('base64url')),
    ).toBeNull();
  });
});

describe('redactSession', () => {
  it('shows programs, extensions and hosts only', () => {
    const [s] = groupSessions([
      act(
        0,
        'shell',
        'API_KEY=abc123 /usr/bin/curl -H "Authorization: Bearer zzz" https://x',
        { sessionId: 'S' },
      ),
      act(1, 'edit', '/home/alice/secret-project/src/Payroll.TS', {
        sessionId: 'S',
      }),
      act(2, 'webfetch', 'https://user:pw@docs.example.com/p?token=abc', {
        sessionId: 'S',
      }),
      act(3, 'mcp', 'github/create_issue', { sessionId: 'S' }),
    ]);
    const r = redactSession(s!, 'Cursor');
    expect(r.steps.map((x) => x.text)).toEqual([
      'curl',
      '.ts',
      'docs.example.com',
      'github',
    ]);
    const json = JSON.stringify(r);
    for (const bad of [
      'abc123',
      'zzz',
      'alice',
      'Payroll',
      'secret-project',
      'pw',
      'token',
      'h1',
    ]) {
      expect(json).not.toContain(bad);
    }
    expect(r.durationSeconds).toBe(180);
  });
});

describe('redaction details', () => {
  const one = (actionId: string, resource: string) => {
    const [s] = groupSessions([act(0, actionId, resource, { sessionId: 'S' })]);
    return redactSession(s!, 'Cursor').steps[0]!.text;
  };
  it('drops internal, single-label and address hosts', () => {
    for (const u of [
      'http://intranet/x',
      'https://10.0.0.5/x',
      'https://8.8.8.8/x',
      'https://git.corp/x',
      'https://wiki.internal/x',
      'https://nas.local/x',
      'https://box.lan/x',
      'https://localhost/x',
    ])
      expect(one('webfetch', u)).toBe('');
    expect(one('webfetch', 'https://Docs.Example.com/a')).toBe(
      'docs.example.com',
    );
  });
  it('shows an MCP server name only for a real MCP call', () => {
    expect(one('mcp', 'github/create_issue')).toBe('github');
    expect(one('weirdtool', 'secretproject/thing')).toBe('');
  });
  it('shows file extensions, never names, and nothing token-shaped', () => {
    expect(one('edit', '/h/a/Payroll2026.xlsx')).toBe('.xlsx');
    expect(one('edit', '/h/a/id_rsa')).toBe('');
    expect(one('edit', '/h/a/notes.mysecretkey123')).toBe('');
    expect(one('shell', 'ghp_abcdefghijklmnopqrstuvwxyz0123456789 --x')).toBe(
      '',
    );
    expect(one('shell', 'AbCdEfGhIjKlMnOpQrStUv0123456789 run')).toBe('');
  });
  it('keeps two accounts on one device and tool apart', () => {
    const s = groupSessions([
      act(0, 'shell', 'ls', { caller: 'uid:1000' }),
      act(1, 'shell', 'ls', { caller: 'uid:1001' }),
    ]);
    expect(s).toHaveLength(2);
  });
  it('finds the hook session of an id-less event among many overlapping sessions', () => {
    const evs: RawEvent[] = [];
    for (let i = 0; i < 300; i++)
      evs.push(
        act(i * 2, 'read', '/a', { sessionId: `S${i}` }),
        act(i * 2 + 1, 'read', '/a', { sessionId: `S${i}` }),
      );
    evs.push({
      id: 'sx',
      eventType: 'secret.touched',
      timestamp: new Date(T0 + (200 * 2 + 0.5) * 60_000),
      data: {
        hostId: 'h1',
        toolId: 'host.cursor',
        pathClass: 'env-file',
        maskedPath: '~/.env',
      },
    });
    const s = groupSessions(evs);
    expect(s).toHaveLength(300);
    expect(s.find((x) => x.counts.secrets === 1)!.steps).toHaveLength(3);
  });
});
