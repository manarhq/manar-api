import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import {
  cursorWhereClause,
  encodeCursor,
  type DecodedCursor,
} from '../common/pagination/cursor-pagination';
import { SITE_CONNECT_ACTION } from '../jail/jail-sites';
import { choicesFor, type DeciderKind } from './approver-directory';

export type ApprovalHistoryStatus =
  'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'REVOKED';

/** The person reading the history. */
export interface HistoryViewer {
  userId: string;
  subject: string;
  /** An approver role: sees and decides everything. */
  admin: boolean;
  /** Not an admin: may decide their own devices' and agents' requests ("admins only" is off). */
  ownerMayDecide: boolean;
}

export interface ApprovalHistoryItem {
  kind: 'agent' | 'host';
  id: string;
  requestedAt: Date;
  status: ApprovalHistoryStatus;
  toolId: string;
  actionId: string;
  resource: string;
  source:
    | { type: 'device'; hostId: string; name: string }
    | { type: 'agent'; agentId: string; name: string; taskId: string };
  riskScore: number | null;
  decision: 'approve_once' | 'approve_8h' | 'approve_always' | 'deny' | null;
  decidedByName: string | null;
  decidedVia: string | null;
  decidedAt: Date | null;
  reason: string | null;
  endReason: string | null;
  expiresAt: Date;
  usedAt: Date | null;
  revokedAt: Date | null;
  revokedByName: string | null;
  revokeNote: string | null;
  usedBeforeRevoke: boolean | null;
  standing: {
    kind: 'grant' | 'block' | 'site_rule';
    id: string;
    mode?: string;
    expiresAt: Date | null;
    revokedAt: Date | null;
    useCount?: number;
  }[];
  allowedDecisions: string[];
  canRevoke: boolean;
}

const HOST_DECISIONS = new Set([
  'approve_once',
  'approve_8h',
  'approve_always',
  'deny',
]);

/**
 * `GET /approvals/history` (3 Nov 2026): agent and device approvals in one list, newest first,
 * every state, with who decided, when, through which channel, what it created, whether it was
 * used, and whether it was revoked. A person who is not an approver sees only their own devices
 * and agents.
 *
 * One cursor over two tables: each is read with the same `(time, id) < cursor` bound and
 * `limit + 1` rows, the two sorted runs are merged, and the page is cut at `limit`. Rows past the
 * cut are read again on the next page, so nothing is skipped or repeated.
 */
export async function listApprovalHistory(
  client: TenantPrismaClient,
  input: {
    limit: number;
    cursor?: DecodedCursor;
    status?: ApprovalHistoryStatus;
    viewer: HistoryViewer;
    now?: Date;
  },
): Promise<{ items: ApprovalHistoryItem[]; nextCursor: string | null }> {
  const { viewer, limit } = input;
  const now = input.now ?? new Date();
  const status = input.status ? { status: input.status } : {};
  const [agentRows, hostRows] = await Promise.all([
    client.approvalRequest.findMany({
      where: {
        ...status,
        ...(viewer.admin ? {} : { agent: { createdBy: viewer.userId } }),
        ...cursorWhereClause('requestedAt', input.cursor),
      },
      orderBy: [{ requestedAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
      include: {
        agent: { select: { displayName: true } },
        grant: { select: { consumedAt: true } },
        decisions: { orderBy: { decidedAt: 'desc' }, take: 1 },
      },
    }),
    client.hostApproval.findMany({
      where: {
        ...status,
        ...(viewer.admin ? {} : { host: { ownerSubject: viewer.subject } }),
        ...cursorWhereClause('createdAt', input.cursor),
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
      include: { host: { select: { hostname: true } } },
    }),
  ]);

  type Merged =
    | { at: Date; id: string; agent: (typeof agentRows)[number] }
    | { at: Date; id: string; host: (typeof hostRows)[number] };
  const merged: Merged[] = [
    ...agentRows.map((agent) => ({
      at: agent.requestedAt,
      id: agent.id,
      agent,
    })),
    ...hostRows.map((host) => ({ at: host.createdAt, id: host.id, host })),
  ].sort((a, b) => b.at.getTime() - a.at.getTime() || (a.id < b.id ? 1 : -1));
  const page = merged.slice(0, limit);
  const last = page[page.length - 1];
  const nextCursor =
    merged.length > limit && last ? encodeCursor(last, last.at) : null;

  const ids = page.map((m) => m.id);
  const pageHosts = page.flatMap((m) => ('host' in m ? [m.host] : []));
  const userIds = new Set<string>();
  const subjects = new Set<string>();
  for (const m of page) {
    if ('agent' in m) {
      const d = m.agent.decisions[0];
      if (d) userIds.add(d.approverId);
      if (m.agent.revokedBy) userIds.add(m.agent.revokedBy);
    } else {
      if (m.host.decidedBy) subjects.add(m.host.decidedBy);
      if (m.host.revokedBy) subjects.add(m.host.revokedBy);
    }
  }
  const [grants, siteRules, people] = await Promise.all([
    ids.length
      ? client.approvalAllowGrant.findMany({ where: { sourceId: { in: ids } } })
      : [],
    pageHosts.some((h) => h.actionId === SITE_CONNECT_ACTION)
      ? client.hostSiteRule.findMany({
          where: {
            source: 'approval',
            hostId: { in: [...new Set(pageHosts.map((h) => h.hostId))] },
          },
        })
      : [],
    userIds.size || subjects.size
      ? client.userProfile.findMany({
          where: {
            OR: [
              { id: { in: [...userIds] } },
              { keycloakSubject: { in: [...subjects] } },
            ],
          },
          select: {
            id: true,
            keycloakSubject: true,
            displayName: true,
            email: true,
          },
        })
      : [],
  ]);
  const nameById = new Map(people.map((p) => [p.id, p.displayName || p.email]));
  const nameBySubject = new Map(
    people.map((p) => [p.keycloakSubject, p.displayName || p.email]),
  );
  // Someone who has left the workspace still decided it: say so rather than show an id.
  const named = (map: Map<string, string>, key: string | null) =>
    key ? (map.get(key) ?? 'A former member') : null;

  const decider: DeciderKind | null = viewer.admin
    ? 'admin'
    : viewer.ownerMayDecide
      ? 'owner'
      : null;
  const live = (status: string, expiresAt: Date) =>
    status === 'PENDING' && expiresAt > now;

  const items = page.map((m): ApprovalHistoryItem => {
    const standing: ApprovalHistoryItem['standing'] = grants
      .filter((g) => g.sourceId === m.id)
      .map((g) => ({
        kind: g.effect === 'BLOCK' ? ('block' as const) : ('grant' as const),
        id: g.id,
        expiresAt: g.expiresAt,
        revokedAt: g.revokedAt,
        useCount: g.useCount,
      }));
    if ('agent' in m) {
      const a = m.agent;
      const d = a.decisions[0];
      const eightHours = standing.some((s) => s.kind === 'grant');
      return {
        kind: 'agent',
        id: a.id,
        requestedAt: a.requestedAt,
        status: a.status,
        toolId: a.toolId,
        actionId: a.actionId,
        resource: a.resource,
        source: {
          type: 'agent',
          agentId: a.agentId,
          name: a.agent.displayName,
          taskId: a.taskId,
        },
        riskScore: a.riskScore,
        decision: !d
          ? null
          : d.decision === 'DENY'
            ? 'deny'
            : eightHours
              ? 'approve_8h'
              : 'approve_once',
        decidedByName: named(nameById, d?.approverId ?? null),
        decidedVia: d ? 'console' : null,
        decidedAt: d?.decidedAt ?? null,
        reason: d?.reason ?? null,
        endReason: a.endReason,
        expiresAt: a.expiresAt,
        usedAt: a.grant?.consumedAt ?? a.releasedAt,
        revokedAt: a.revokedAt,
        revokedByName: named(nameById, a.revokedBy),
        revokeNote: a.revokeNote,
        usedBeforeRevoke: a.usedBeforeRevoke,
        standing,
        allowedDecisions: live(a.status, a.expiresAt)
          ? choicesFor(decider, a).filter((c) => c !== 'approve_always')
          : [],
        canRevoke: a.status === 'APPROVED' && decider !== null,
      };
    }
    const h = withdrawnLegacy(m.host);
    if (h.actionId === SITE_CONNECT_ACTION) {
      const rule = siteRules.find(
        (r) =>
          r.hostId === h.hostId &&
          r.toolId === h.toolId &&
          r.site === h.resource,
      );
      if (rule)
        standing.push({
          kind: 'site_rule',
          id: rule.id,
          mode: rule.mode,
          expiresAt: rule.expiresAt,
          revokedAt: null,
        });
    }
    return {
      kind: 'host',
      id: h.id,
      requestedAt: h.createdAt,
      status: h.status,
      toolId: h.toolId,
      actionId: h.actionId,
      resource: h.resource,
      source: { type: 'device', hostId: h.hostId, name: h.host.hostname },
      riskScore: null,
      decision:
        h.decision && HOST_DECISIONS.has(h.decision)
          ? (h.decision as ApprovalHistoryItem['decision'])
          : null,
      decidedByName: named(nameBySubject, h.decidedBy),
      decidedVia: h.decidedVia,
      decidedAt: h.decidedAt,
      reason: null,
      endReason: h.endReason,
      expiresAt: h.expiresAt,
      usedAt: h.usedAt,
      revokedAt: h.revokedAt,
      revokedByName: named(nameBySubject, h.revokedBy),
      revokeNote: h.revokeNote,
      usedBeforeRevoke: h.usedBeforeRevoke,
      standing,
      allowedDecisions: live(h.status, h.expiresAt)
        ? choicesFor(decider, h)
        : [],
      canRevoke: h.status === 'APPROVED' && decider !== null,
    };
  });
  return { items, nextCursor };
}

/**
 * Before 3 Nov 2026 a device that stopped waiting for a new-site answer sent "deny", stored as a
 * deny by the device owner. Only JAIL's own timeout sends that (WARDEN shows no buttons for sites),
 * so it is shown for what it was. The row itself is left as written.
 */
function withdrawnLegacy<
  T extends {
    status: string;
    actionId: string;
    decision: string | null;
    decidedVia: string | null;
    decidedBy: string | null;
    endReason: string | null;
  },
>(h: T): T {
  if (
    h.decidedVia !== 'device' ||
    h.decision !== 'deny' ||
    h.actionId !== SITE_CONNECT_ACTION
  )
    return h;
  return {
    ...h,
    status: 'EXPIRED',
    endReason: 'withdrawn',
    decision: null,
    decidedVia: null,
    decidedBy: null,
  };
}
