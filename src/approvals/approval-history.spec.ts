import { describe, expect, it } from 'vitest';
import { parseCursor } from '../common/pagination/cursor-pagination';
import { listApprovalHistory, type HistoryViewer } from './approval-history';

const t = (min: number) => new Date(Date.UTC(2026, 10, 3, 0, min));

type Row = Record<string, unknown> & { id: string };

/** findMany with the `(time, id) < cursor` OR clause, desc order and take, as Prisma applies them. */
function rowsTable(rows: Row[], timeField: string) {
  return {
    findMany: ({
      where,
      take,
    }: {
      where: Record<string, unknown>;
      take: number;
    }) => {
      const or = where.OR as { [k: string]: unknown }[] | undefined;
      const before = (r: Row) => {
        if (!or) return true;
        const bound = (or[0]![timeField] as { lt: Date }).lt;
        const id = (or[1]!.id as { lt: string }).lt;
        const at = (r[timeField] as Date).getTime();
        return at < bound.getTime() || (at === bound.getTime() && r.id < id);
      };
      const own = (r: Row) =>
        (!where.agent ||
          r.creator === (where.agent as { createdBy: string }).createdBy) &&
        (!where.host ||
          r.owner === (where.host as { ownerSubject: string }).ownerSubject) &&
        (!where.status || r.status === where.status);
      return Promise.resolve(
        rows
          .filter((r) => before(r) && own(r))
          .sort(
            (a, b) =>
              (b[timeField] as Date).getTime() -
                (a[timeField] as Date).getTime() || (a.id < b.id ? 1 : -1),
          )
          .slice(0, take),
      );
    },
  };
}

function client() {
  const agent = (id: string, min: number, extra: Partial<Row> = {}): Row => ({
    id,
    requestedAt: t(min),
    status: 'APPROVED',
    agentId: 'agent-1',
    taskId: 'task-1',
    toolId: 'gitlab',
    actionId: 'merge',
    resource: 'repo/x',
    riskScore: 40,
    expiresAt: t(min + 30),
    releasedAt: null,
    revokedAt: null,
    revokedBy: null,
    revokeNote: null,
    usedBeforeRevoke: null,
    endReason: null,
    creator: 'u-dev',
    agent: {
      displayName: 'Release bot',
      createdBy: (extra.creator as string | undefined) ?? 'u-dev',
    },
    grant: { consumedAt: t(min + 1) },
    decisions: [
      {
        decision: 'APPROVE',
        approverId: 'u-boss',
        decidedAt: t(min),
        reason: 'ok',
      },
    ],
    ...extra,
  });
  const host = (id: string, min: number, extra: Partial<Row> = {}): Row => ({
    id,
    createdAt: t(min),
    status: 'EXPIRED',
    hostId: 'h1',
    toolId: 'host.claude-code',
    actionId: 'site.connect',
    resource: 'example.com',
    decision: null,
    decidedBy: null,
    decidedVia: null,
    decidedAt: null,
    expiresAt: t(min + 2),
    usedAt: null,
    revokedAt: null,
    revokedBy: null,
    revokeNote: null,
    usedBeforeRevoke: null,
    endReason: 'withdrawn',
    owner: 'sub-dev',
    host: {
      hostname: 'dev-laptop',
      ownerSubject: (extra.owner as string | undefined) ?? 'sub-dev',
    },
    ...extra,
  });
  return {
    approvalRequest: rowsTable(
      [agent('a1', 1), agent('a3', 3), agent('a5', 5, { creator: 'u-other' })],
      'requestedAt',
    ),
    hostApproval: rowsTable(
      [
        host('h2', 2),
        host('h4', 4, {
          status: 'APPROVED',
          decision: 'approve_always',
          decidedBy: 'sub-boss',
          decidedVia: 'console',
          endReason: null,
        }),
        host('h6', 6, {
          owner: 'sub-other',
          // Written before 3 Nov 2026: JAIL's timeout stored as a device deny.
          status: 'DENIED',
          decision: 'deny',
          decidedVia: 'device',
          decidedBy: 'sub-other',
          endReason: null,
        }),
      ],
      'createdAt',
    ),
    approvalAllowGrant: { findMany: () => Promise.resolve([]) },
    toolAction: { findMany: () => Promise.resolve([]) },
    hostSiteRule: {
      findMany: () =>
        Promise.resolve([
          {
            id: 'rule-1',
            hostId: 'h1',
            toolId: 'host.claude-code',
            site: 'example.com',
            mode: 'ALLOW',
            expiresAt: null,
            source: 'approval',
          },
        ]),
    },
    userProfile: {
      findMany: () =>
        Promise.resolve([
          {
            id: 'u-boss',
            keycloakSubject: 'sub-boss',
            displayName: 'Sara',
            email: 's@x',
          },
        ]),
    },
  };
}

const admin: HistoryViewer = {
  userId: 'u-boss',
  subject: 'sub-boss',
  admin: true,
  operator: true,
  adminsOnly: false,
  company: true,
};
const dev: HistoryViewer = {
  userId: 'u-dev',
  subject: 'sub-dev',
  admin: false,
  operator: true,
  adminsOnly: false,
  company: true,
};

describe('approval history', () => {
  it('pages agent and device approvals together, newest first, without skipping or repeating', async () => {
    const c = client();
    const seen: string[] = [];
    let cursor: string | null = null;
    do {
      const page = await listApprovalHistory(c as never, {
        limit: 2,
        cursor: parseCursor(cursor ?? undefined),
        viewer: admin,
      });
      seen.push(...page.items.map((i) => i.id));
      cursor = page.nextCursor;
    } while (cursor);
    expect(seen).toEqual(['h6', 'a5', 'h4', 'a3', 'h2', 'a1']);
  });

  it('says who decided, through what, what it created, and when it was used', async () => {
    const page = await listApprovalHistory(client() as never, {
      limit: 10,
      viewer: admin,
    });
    const h4 = page.items.find((i) => i.id === 'h4')!;
    expect(h4).toMatchObject({
      kind: 'host',
      decision: 'approve_always',
      decidedByName: 'Sara',
      decidedVia: 'console',
      source: { type: 'device', name: 'dev-laptop' },
      canRevoke: true,
    });
    expect(h4.standing).toContainEqual(
      expect.objectContaining({ kind: 'site_rule', id: 'rule-1' }),
    );
    const a1 = page.items.find((i) => i.id === 'a1')!;
    expect(a1).toMatchObject({
      decision: 'approve_once',
      decidedByName: 'Sara',
      reason: 'ok',
      usedAt: t(2),
    });
    expect(page.items.find((i) => i.id === 'h6')).toMatchObject({
      status: 'EXPIRED',
      endReason: 'withdrawn',
      decision: null,
      decidedByName: null,
    });
    expect(page.items.find((i) => i.id === 'h2')).toMatchObject({
      status: 'EXPIRED',
      endReason: 'withdrawn',
      decidedByName: null,
    });
  });

  it('a member sees only their own devices and agents', async () => {
    const page = await listApprovalHistory(client() as never, {
      limit: 10,
      viewer: dev,
    });
    expect(page.items.map((i) => i.id)).toEqual(['h4', 'a3', 'h2', 'a1']);
  });

  it('with "admins only" a member still sees their own history but can act on none of it', async () => {
    const page = await listApprovalHistory(client() as never, {
      limit: 10,
      viewer: { ...dev, adminsOnly: true },
    });
    expect(page.items.length).toBeGreaterThan(0);
    expect(
      page.items.every((i) => !i.canRevoke && i.allowedDecisions.length === 0),
    ).toBe(true);
  });
});
