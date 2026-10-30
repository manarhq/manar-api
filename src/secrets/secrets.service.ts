import { Injectable } from '@nestjs/common';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditActor } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  cursorWhereClause,
  toCursorPage,
  type CursorPage,
  type DecodedCursor,
} from '../common/pagination/cursor-pagination';
import type {
  PrismaClient as TenantPrismaClient,
  SecretEvent,
} from '../generated/tenant-client/client';
import { SecretAlertBus } from './secret-alert-bus';
import { maskHome, type HostEvent } from './secrets.validation';

export class SecretsNotFoundError extends Error {}
export class SecretsConflictError extends Error {}

const WATCH_TYPES = ['secret.watch.available', 'secret.watch.unavailable'];
const FUTURE_SLACK_MS = 5 * 60_000;
const ACCESS_TTL_MS = 10 * 60_000;
const MAX_PENDING_ACCESS_PER_HOST = 50;
const hostActor = (hostId: string): AuditActor => ({
  type: 'system',
  id: `host:${hostId}`,
});

export interface TimelineQuery {
  hostId?: string;
  toolId?: string;
  type?: string;
  from?: Date;
  to?: Date;
  limit: number;
  cursor?: DecodedCursor;
}

/** Watcher events, the vault and its access requests. Every query is on the caller's tenant client. */
@Injectable()
export class SecretsService {
  constructor(
    private readonly audit: AuditService,
    private readonly bus: SecretAlertBus,
  ) {}

  /** `POST /host/v1/events`: stores a validated batch, audits secret.* and raises alerts. */
  async ingest(
    client: TenantPrismaClient,
    tenantId: string,
    hostId: string,
    events: HostEvent[],
  ): Promise<{ accepted: number }> {
    const now = Date.now();
    const rows = events.map((e) => ({
      hostId,
      type: e.type,
      toolId: e.toolId ?? null,
      process: e.process ?? null,
      pathClass: e.pathClass ?? null,
      maskedPath: e.maskedPath ? maskHome(e.maskedPath) : null,
      blocked: e.blocked ?? false,
      at: new Date(Math.min(e.at.getTime(), now + FUTURE_SLACK_MS)),
    }));
    await client.secretEvent.createMany({ data: rows });
    for (const r of rows) {
      if (WATCH_TYPES.includes(r.type)) continue;
      await this.audit.recordSafely(client, tenantId, {
        eventType:
          r.type as (typeof AUDIT_EVENT_TYPES)[keyof typeof AUDIT_EVENT_TYPES],
        actor: hostActor(hostId),
        data: {
          hostId,
          toolId: r.toolId,
          process: r.process,
          pathClass: r.pathClass,
          maskedPath: r.maskedPath,
          blocked: r.blocked,
          at: r.at.toISOString(),
        },
      });
      if (r.type === 'secret.touched' && r.toolId) {
        this.bus.emit({
          tenantId,
          hostId,
          toolId: r.toolId,
          process: r.process ?? '',
          pathClass: r.pathClass ?? '',
          maskedPath: r.maskedPath ?? '',
          blocked: r.blocked,
          at: r.at,
        });
      }
    }
    return { accepted: rows.length };
  }

  async timeline(
    client: TenantPrismaClient,
    q: TimelineQuery,
  ): Promise<CursorPage<SecretEvent & { hostname: string | null }>> {
    const rows = await client.secretEvent.findMany({
      where: {
        ...(q.hostId ? { hostId: q.hostId } : {}),
        ...(q.toolId ? { toolId: q.toolId } : {}),
        type: q.type ? q.type : { notIn: WATCH_TYPES },
        ...(q.from || q.to
          ? {
              at: {
                ...(q.from ? { gte: q.from } : {}),
                ...(q.to ? { lte: q.to } : {}),
              },
            }
          : {}),
        ...cursorWhereClause('at', q.cursor),
      },
      orderBy: [{ at: 'desc' }, { id: 'desc' }],
      take: q.limit + 1,
    });
    const page = toCursorPage(rows, q.limit, (r) => r.at);
    const hosts = await client.host.findMany({
      where: { id: { in: [...new Set(page.items.map((r) => r.hostId))] } },
      select: { id: true, hostname: true },
    });
    const names = new Map(hosts.map((h) => [h.id, h.hostname]));
    return {
      nextCursor: page.nextCursor,
      items: page.items.map((r) => ({
        ...r,
        hostname: names.get(r.hostId) ?? null,
      })),
    };
  }

  /** What each tool touched in the last `days` days, per path class; plus watcher status and vault per device. */
  async overview(client: TenantPrismaClient, days: number) {
    const since = new Date(Date.now() - days * 86_400_000);
    const [groups, hosts, vault, pending] = await Promise.all([
      client.secretEvent.groupBy({
        by: ['toolId', 'pathClass', 'blocked'],
        where: {
          type: 'secret.touched',
          at: { gte: since },
          toolId: { not: null },
        },
        _count: { _all: true },
        _max: { at: true },
      }),
      client.host.findMany({
        where: { status: 'APPROVED' },
        select: { id: true, hostname: true, os: true },
        orderBy: { hostname: 'asc' },
        take: 200,
      }),
      client.secretVault.findMany({
        orderBy: { createdAt: 'desc' },
        take: 500,
      }),
      client.secretVaultAccess.count({
        where: {
          status: 'PENDING',
          createdAt: { gte: new Date(Date.now() - ACCESS_TTL_MS) },
        },
      }),
    ]);
    const tools = new Map<
      string,
      {
        toolId: string;
        touched: number;
        blocked: number;
        classes: Record<string, number>;
        lastAt: Date | null;
      }
    >();
    for (const g of groups) {
      const id = g.toolId as string;
      const t = tools.get(id) ?? {
        toolId: id,
        touched: 0,
        blocked: 0,
        classes: {},
        lastAt: null,
      };
      t.touched += g._count._all;
      if (g.blocked) t.blocked += g._count._all;
      if (g.pathClass)
        t.classes[g.pathClass] = (t.classes[g.pathClass] ?? 0) + g._count._all;
      if (g._max.at && (!t.lastAt || g._max.at > t.lastAt))
        t.lastAt = g._max.at;
      tools.set(id, t);
    }
    const devices = await Promise.all(
      hosts.map(async (h) => {
        const last = await client.secretEvent.findFirst({
          where: { hostId: h.id, type: { in: WATCH_TYPES } },
          orderBy: [{ at: 'desc' }, { id: 'desc' }],
          select: { type: true, at: true },
        });
        return {
          hostId: h.id,
          hostname: h.hostname,
          os: h.os,
          // Honest label: no report at all is "unknown", never a green tick.
          watcher: !last
            ? 'unknown'
            : last.type === 'secret.watch.available'
              ? 'ok'
              : 'monitoring unavailable',
          vault: vault.filter((v) => v.hostId === h.id),
        };
      }),
    );
    return {
      days,
      tools: [...tools.values()].sort((a, b) => b.touched - a.touched),
      devices,
      pendingAccess: pending,
    };
  }

  private async approvedHost(client: TenantPrismaClient, hostId: string) {
    const host = await client.host.findUnique({ where: { id: hostId } });
    if (!host || host.status !== 'APPROVED') {
      throw new SecretsNotFoundError('No approved device with that id');
    }
    return host;
  }

  /** Console: ask a device to move one secret into its vault. */
  async requestVault(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    hostId: string,
    kind: string,
    ref: string,
  ) {
    await this.approvedHost(client, hostId);
    const existing = await client.secretVault.findUnique({
      where: { hostId_kind_ref: { hostId, kind, ref } },
    });
    if (
      existing &&
      (existing.state === 'STORED' || existing.state === 'RESTORE_REQUESTED')
    ) {
      throw new SecretsConflictError('This secret is already in the vault');
    }
    return client.secretVault.upsert({
      where: { hostId_kind_ref: { hostId, kind, ref } },
      create: { hostId, kind, ref, requestedBy: actor.id },
      update: { state: 'REQUESTED', requestedBy: actor.id, detail: null },
    });
  }

  /** Console: "Restore to file". */
  async requestRestore(
    client: TenantPrismaClient,
    hostId: string,
    kind: string,
    ref: string,
  ) {
    await this.approvedHost(client, hostId);
    const row = await client.secretVault.findUnique({
      where: { hostId_kind_ref: { hostId, kind, ref } },
    });
    if (!row || row.state !== 'STORED') {
      throw new SecretsConflictError('This secret is not in the vault');
    }
    return client.secretVault.update({
      where: { id: row.id },
      data: { state: 'RESTORE_REQUESTED' },
    });
  }

  /** Device: what to do now. */
  async instructions(client: TenantPrismaClient, hostId: string) {
    const rows = await client.secretVault.findMany({
      where: { hostId, state: { in: ['REQUESTED', 'RESTORE_REQUESTED'] } },
      orderBy: { createdAt: 'asc' },
      take: 50,
    });
    return {
      vault: rows.map((r) => ({
        kind: r.kind,
        ref: r.ref,
        action: r.state === 'REQUESTED' ? 'store' : 'restore',
      })),
    };
  }

  /** Device: the result of an instruction (after it verified the read-back, for STORED). */
  async report(
    client: TenantPrismaClient,
    tenantId: string,
    hostId: string,
    kind: string,
    ref: string,
    state: 'STORED' | 'RESTORED' | 'FAILED',
    detail?: string,
  ) {
    const row = await client.secretVault.findUnique({
      where: { hostId_kind_ref: { hostId, kind, ref } },
    });
    if (!row) throw new SecretsNotFoundError('No such vault entry');
    let next: string;
    if (state === 'STORED' && row.state === 'REQUESTED') next = 'STORED';
    else if (state === 'RESTORED' && row.state === 'RESTORE_REQUESTED')
      next = 'RESTORED';
    else if (state === 'FAILED')
      next = row.state === 'RESTORE_REQUESTED' ? 'STORED' : 'FAILED';
    else
      throw new SecretsConflictError(
        'That report does not fit the entry state',
      );
    await client.secretVault.update({
      where: { id: row.id },
      data: { state: next, detail: detail ?? null },
    });
    if (state !== 'FAILED') {
      await this.audit.recordSafely(client, tenantId, {
        eventType:
          state === 'STORED'
            ? AUDIT_EVENT_TYPES.SECRET_VAULT_STORED
            : AUDIT_EVENT_TYPES.SECRET_VAULT_RESTORED,
        actor: hostActor(hostId),
        data: { hostId, kind, ref },
      });
    }
    return { state: next };
  }

  /** Device: a program wants a vaulted secret. One open request per (device, secret, program). */
  async createAccess(
    client: TenantPrismaClient,
    hostId: string,
    kind: string,
    ref: string,
    program: string,
  ) {
    const vault = await client.secretVault.findUnique({
      where: { hostId_kind_ref: { hostId, kind, ref } },
    });
    if (!vault || vault.state !== 'STORED') {
      throw new SecretsNotFoundError('That secret is not in the vault');
    }
    const fresh = new Date(Date.now() - ACCESS_TTL_MS);
    const open = await client.secretVaultAccess.findFirst({
      where: {
        hostId,
        kind,
        ref,
        program,
        status: 'PENDING',
        createdAt: { gte: fresh },
      },
    });
    if (open) return { id: open.id, status: open.status };
    const count = await client.secretVaultAccess.count({
      where: { hostId, status: 'PENDING', createdAt: { gte: fresh } },
    });
    if (count >= MAX_PENDING_ACCESS_PER_HOST) {
      throw new SecretsConflictError('Too many open requests for this device');
    }
    const row = await client.secretVaultAccess.create({
      data: { hostId, kind, ref, program },
    });
    return { id: row.id, status: row.status };
  }

  /** Device: poll one request (only its own). An old PENDING reads as DENY. */
  async getAccess(client: TenantPrismaClient, hostId: string, id: string) {
    const row = await client.secretVaultAccess.findFirst({
      where: { id, hostId },
    });
    if (!row) throw new SecretsNotFoundError('No such request');
    const expired =
      row.status === 'PENDING' &&
      row.createdAt.getTime() < Date.now() - ACCESS_TTL_MS;
    return { id: row.id, status: expired ? 'DENY' : row.status };
  }

  /** Console: open requests (newest first). */
  listAccess(client: TenantPrismaClient) {
    return client.secretVaultAccess.findMany({
      where: {
        status: 'PENDING',
        createdAt: { gte: new Date(Date.now() - ACCESS_TTL_MS) },
      },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
  }

  /** Console: the person's decision. Audited as released or denied. */
  async decideAccess(
    client: TenantPrismaClient,
    tenantId: string,
    actor: AuditActor,
    id: string,
    decision: 'ALLOW_ONCE' | 'ALLOW_8H' | 'ALLOW_ALWAYS' | 'DENY',
  ) {
    const row = await client.secretVaultAccess.findUnique({ where: { id } });
    if (!row) throw new SecretsNotFoundError('No such request');
    const done = await client.secretVaultAccess.updateMany({
      where: {
        id,
        status: 'PENDING',
        createdAt: { gte: new Date(Date.now() - ACCESS_TTL_MS) },
      },
      data: { status: decision, decidedBy: actor.id, decidedAt: new Date() },
    });
    if (done.count !== 1)
      throw new SecretsConflictError(
        'This request was already decided or has expired',
      );
    await this.audit.recordSafely(client, tenantId, {
      eventType:
        decision === 'DENY'
          ? AUDIT_EVENT_TYPES.SECRET_VAULT_DENIED
          : AUDIT_EVENT_TYPES.SECRET_VAULT_RELEASED,
      actor,
      data: {
        hostId: row.hostId,
        kind: row.kind,
        ref: row.ref,
        program: row.program,
        decision,
      },
    });
    await client.secretEvent.create({
      data: {
        hostId: row.hostId,
        type:
          decision === 'DENY' ? 'secret.vault.denied' : 'secret.vault.released',
        process: row.program,
        pathClass: row.kind,
        maskedPath: row.ref,
        blocked: decision === 'DENY',
        at: new Date(),
      },
    });
    return { id, status: decision };
  }
}
