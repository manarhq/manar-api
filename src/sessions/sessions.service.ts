import { Injectable, NotFoundException } from '@nestjs/common';
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
const EVENT_TYPES = [
  'host.action_decided',
  'secret.touched',
  'secret.vault.denied',
  'approval.approved',
  'approval.denied',
];
/** Rows read per request: a bound, not a page. A busier window shows its newest sessions. */
const MAX_EVENTS = 20_000;

@Injectable()
export class SessionsService {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
    private readonly shares: ReportShareService,
  ) {}

  private async load(
    tenantId: string,
    days: number,
    hostId?: string,
    toolId?: string,
  ): Promise<{ sessions: Session[]; hostnames: Map<string, string> }> {
    const client = await this.tenants.getClient(tenantId);
    const rows = await client.auditEvent.findMany({
      where: {
        eventType: { in: EVENT_TYPES },
        timestamp: { gte: new Date(Date.now() - days * DAY_MS) },
      },
      orderBy: { timestamp: 'desc' },
      take: MAX_EVENTS,
      select: { id: true, eventType: true, timestamp: true, data: true },
    });
    const events: RawEvent[] = rows.map((r) => ({
      id: r.id,
      eventType: r.eventType,
      timestamp: r.timestamp,
      data: (r.data ?? {}) as Record<string, unknown>,
    }));
    const sessions = groupSessions(events).filter(
      (s) =>
        (!hostId || s.hostId === hostId) && (!toolId || s.toolId === toolId),
    );
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
  async list(tenantId: string, days: number, hostId?: string) {
    const { sessions, hostnames } = await this.load(tenantId, days, hostId);
    return {
      sessions: sessions.slice(0, 200).map(({ steps, ...s }) => ({
        ...s,
        stepCount: steps.length,
        hostname: hostnames.get(s.hostId) ?? null,
        toolName: hostTool(s.toolId)?.name ?? s.toolId,
      })),
    };
  }

  async get(tenantId: string, id: string) {
    const p = parseSessionId(id);
    if (!p) throw new NotFoundException('Session not found');
    const { sessions, hostnames } = await this.load(
      tenantId,
      30,
      p.hostId,
      p.toolId,
    );
    const s = sessions.find((x) => x.id === id);
    if (!s) throw new NotFoundException('Session not found');
    return {
      ...s,
      hostname: hostnames.get(s.hostId) ?? null,
      toolName: hostTool(s.toolId)?.name ?? s.toolId,
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
