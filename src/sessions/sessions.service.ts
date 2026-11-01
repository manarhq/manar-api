import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { hostTool } from '../tools/host-actions';
import { ReportShareService } from '../workspace/report-share.service';
import {
  groupSessions,
  parseSessionId,
  redactSession,
  type RawEvent,
  type Session,
} from './sessions';

const DAY_MS = 86_400_000;
const ACTION_TYPES = [
  'host.action_decided',
  'secret.touched',
  'secret.vault.denied',
];
const APPROVAL_TYPES = ['approval.approved', 'approval.denied'];
/**
 * Work per request is bounded: at most PER_HOST newest events of each device (so one noisy device
 * cannot push the others out) and MAX_EVENTS in all. A busier window shows its newest sessions.
 */
const PER_HOST = 1500;
const MAX_EVENTS = 20_000;
const PAGE = 200;

interface Row {
  id: string;
  eventType: string;
  timestamp: Date;
  data: Record<string, unknown> | null;
}

@Injectable()
export class SessionsService {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
    private readonly shares: ReportShareService,
  ) {}

  /**
   * Reads in SQL: the host and tool filters run in the database (partial expression index on
   * data->>'hostId'), then the approvals those actions opened, by id.
   */
  private async load(
    tenantId: string,
    from: Date,
    to: Date,
    hostId?: string,
    toolId?: string,
    perHost = PER_HOST,
  ): Promise<{ sessions: Session[]; hostnames: Map<string, string> }> {
    const client = await this.tenants.getClient(tenantId);
    const rows = await client.$queryRaw<Row[]>(Prisma.sql`
      SELECT id, "eventType", "timestamp", data FROM (
        SELECT id, "eventType", "timestamp", data,
          row_number() OVER (PARTITION BY data->>'hostId' ORDER BY "timestamp" DESC) AS rn
        FROM audit_events
        WHERE "eventType" IN (${Prisma.join(ACTION_TYPES)})
          AND "timestamp" >= ${from} AND "timestamp" < ${to}
          ${hostId ? Prisma.sql`AND data->>'hostId' = ${hostId}` : Prisma.empty}
          ${toolId ? Prisma.sql`AND data->>'toolId' = ${toolId}` : Prisma.empty}
      ) x WHERE rn <= ${perHost}
      ORDER BY "timestamp" DESC LIMIT ${MAX_EVENTS}`);
    const approvalIds = [
      ...new Set(
        rows
          .map((r) => r.data?.approvalId)
          .filter((v): v is string => typeof v === 'string' && v.length > 0),
      ),
    ].slice(0, 5000);
    const approvals = approvalIds.length
      ? await client.$queryRaw<Row[]>(Prisma.sql`
          SELECT id, "eventType", "timestamp", data FROM audit_events
          WHERE "eventType" IN (${Prisma.join(APPROVAL_TYPES)})
            AND data->>'approvalRequestId' = ANY(${approvalIds}::text[])`)
      : [];
    const events: RawEvent[] = [...rows, ...approvals].map((r) => ({
      id: r.id,
      eventType: r.eventType,
      timestamp: r.timestamp,
      data: r.data ?? {},
    }));
    const sessions = groupSessions(events);
    const hosts = await client.host.findMany({
      where: { id: { in: [...new Set(sessions.map((s) => s.hostId))] } },
      select: { id: true, hostname: true },
    });
    return {
      sessions,
      hostnames: new Map(hosts.map((h) => [h.id, h.hostname])),
    };
  }

  /** `GET /sessions`: summaries, newest first, without the steps. */
  /**
   * `GET /sessions`: summaries, newest first, without the steps. `before` pages back in time: pass
   * the `nextBefore` of the previous page.
   */
  async list(tenantId: string, days: number, hostId?: string, before?: Date) {
    const to = before ?? new Date();
    const from = new Date(to.getTime() - days * DAY_MS);
    const { sessions, hostnames } = await this.load(tenantId, from, to, hostId);
    const page = sessions.slice(0, PAGE);
    return {
      sessions: page.map(({ steps, ...s }) => ({
        ...s,
        stepCount: steps.length,
        hostname: hostnames.get(s.hostId) ?? null,
        toolName: hostTool(s.toolId)?.name ?? 'other',
      })),
      nextBefore:
        sessions.length > PAGE ? page[page.length - 1]!.startedAt : null,
    };
  }

  async get(tenantId: string, id: string) {
    const p = parseSessionId(id);
    if (!p) throw new NotFoundException('Session not found');
    const to = new Date(Date.now() + 1000);
    const { sessions, hostnames } = await this.load(
      tenantId,
      new Date(to.getTime() - 30 * DAY_MS),
      to,
      p.hostId,
      p.toolId,
      5000,
    );
    const s = sessions.find((x) => x.id === id);
    if (!s) throw new NotFoundException('Session not found');
    return {
      ...s,
      hostname: hostnames.get(s.hostId) ?? null,
      toolName: hostTool(s.toolId)?.name ?? 'other',
    };
  }

  /** `POST /sessions/:id/share`: a public, revocable link to the redacted copy taken now. */
  async share(tenantId: string, userId: string, id: string) {
    const s = await this.get(tenantId, id);
    const shared = redactSession(s, s.toolName);
    const created = await this.shares.createSession(tenantId, userId, shared);
    const client = await this.tenants.getClient(tenantId);
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.SESSION_SHARED,
      actor: { type: 'human', id: userId },
      data: { hostId: s.hostId, toolId: s.toolId, steps: s.steps.length },
    });
    return created;
  }
}
