import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { z } from 'zod';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditActor } from '../audit/audit-event-types';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ensureHostTools, hostTool } from '../tools/host-actions';
import type { ProtectMode } from '../tools/host-actions';

/** A device that has not reported for this long is shown as `monitoring unavailable`. */
export const MONITORING_STALE_MS = 30 * 60 * 1000;
const MAX_TOOLS = 64;

export const InventoryRequestSchema = z.object({
  tools: z
    .array(
      z.object({
        id: z
          .string()
          .regex(/^(host\.[a-z0-9-]{1,40}|other:[a-z0-9._-]{1,60})$/),
        name: z.string().min(1).max(100),
        version: z.string().max(64).nullish(),
        path: z.string().max(512).nullish(),
        protected: z.boolean(),
        protectMode: z.enum(['hook', 'mcp', 'gateway', 'none']),
        changes: z.array(z.string().max(400)).max(20).default([]),
      }),
    )
    .max(MAX_TOOLS),
});
export type InventoryRequest = z.infer<typeof InventoryRequestSchema>;

export type EnforcementLabel =
  'governed' | 'observed-only' | 'monitoring unavailable';

/**
 * The label a tool has earned (CLAUDE.md 4.3). Governed needs a hook that the catalogue says the
 * tool has AND that the device reports as installed. MCP wrapping and gateway routing gate only part
 * of a tool's actions, so they stay observed-only. A stale device is never labelled from old data.
 */
export function enforcementLabel(
  toolId: string,
  tool: { protected: boolean; protectMode: string },
  online: boolean,
): EnforcementLabel {
  if (!online) return 'monitoring unavailable';
  const def = hostTool(toolId);
  return tool.protected &&
    tool.protectMode === 'hook' &&
    def?.modes.includes('hook')
    ? 'governed'
    : 'observed-only';
}

/** What the catalogue allows, never more than the device claims. */
export function effectiveProtection(
  toolId: string,
  protectedFlag: boolean,
  mode: ProtectMode,
): { protected: boolean; protectMode: ProtectMode } {
  const allowed = (hostTool(toolId)?.modes ?? []) as readonly string[];
  if (!protectedFlag || mode === 'none' || !allowed.includes(mode)) {
    return { protected: false, protectMode: 'none' };
  }
  return { protected: true, protectMode: mode };
}

@Injectable()
export class HostToolsService {
  private readonly logger = new Logger(HostToolsService.name);
  private readonly registered = new Set<string>();

  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  /** `POST /host/v1/inventory`: the device's full list of AI tools. */
  async report(
    host: { hostId: string; tenantId: string },
    input: InventoryRequest,
  ): Promise<{ count: number }> {
    const client = await this.tenants.getClient(host.tenantId);
    const now = new Date();
    const ids = new Set<string>();
    for (const t of input.tools) {
      if (ids.has(t.id))
        throw new BadRequestException(`duplicate tool ${t.id}`);
      ids.add(t.id);
      if (t.id.startsWith('host.') && !hostTool(t.id)) {
        throw new BadRequestException(`unknown tool ${t.id}`);
      }
    }
    if (!this.registered.has(host.tenantId)) {
      await ensureHostTools(client);
      this.registered.add(host.tenantId);
    }
    const existing = await client.hostTool.findMany({
      where: { hostId: host.hostId },
    });
    const byId = new Map(existing.map((e) => [e.toolId, e]));
    const actor: AuditActor = { type: 'system', id: `host:${host.hostId}` };
    const events: Array<{ type: string; toolId: string; mode: string }> = [];

    for (const t of input.tools) {
      const eff = effectiveProtection(t.id, t.protected, t.protectMode);
      if (t.protected && !eff.protected) {
        this.logger.warn(
          `host ${host.hostId} reported ${t.id} as protected by ${t.protectMode}, which the catalogue does not allow: stored as unprotected`,
        );
      }
      const prev = byId.get(t.id);
      const data = {
        name: t.name,
        version: t.version ?? null,
        path: t.path ?? null,
        protected: eff.protected,
        protectMode: eff.protectMode,
        changes: t.changes,
        lastSeenAt: now,
        missing: false,
      };
      await client.hostTool.upsert({
        where: { hostId_toolId: { hostId: host.hostId, toolId: t.id } },
        create: { hostId: host.hostId, toolId: t.id, ...data },
        update: data,
      });
      if (!prev)
        events.push({
          type: AUDIT_EVENT_TYPES.TOOL_DISCOVERED,
          toolId: t.id,
          mode: eff.protectMode,
        });
      if (
        (prev?.protected ?? false) !== eff.protected &&
        (prev || eff.protected)
      ) {
        events.push({
          type: eff.protected
            ? AUDIT_EVENT_TYPES.TOOL_PROTECTED
            : AUDIT_EVENT_TYPES.TOOL_UNPROTECTED,
          toolId: t.id,
          mode: eff.protected ? eff.protectMode : (prev?.protectMode ?? 'none'),
        });
      }
    }
    // A tool missing from one scan is marked, not deleted: the owner's choice must survive a
    // scan that missed it, and the tool shows again as soon as it is found.
    await client.hostTool.updateMany({
      where: { hostId: host.hostId, toolId: { notIn: [...ids] } },
      data: { missing: true, protected: false, protectMode: 'none' },
    });
    await client.host.update({
      where: { id: host.hostId },
      data: { lastSeenAt: now },
    });
    for (const e of events) {
      await this.audit.recordSafely(client, host.tenantId, {
        eventType:
          e.type as (typeof AUDIT_EVENT_TYPES)[keyof typeof AUDIT_EVENT_TYPES],
        actor,
        data: {
          hostId: host.hostId,
          toolId: e.toolId,
          protectMode: e.mode,
          stage: 'applied',
        },
      });
    }
    return { count: input.tools.length };
  }

  /** Part of `GET /host/v1/config`: tools whose owner turned protection off. */
  async instructions(host: {
    hostId: string;
    tenantId: string;
  }): Promise<{ unprotect: string[] }> {
    const client = await this.tenants.getClient(host.tenantId);
    const rows = await client.hostTool.findMany({
      where: { hostId: host.hostId, desiredProtection: false },
      select: { toolId: true },
    });
    return { unprotect: rows.map((r) => r.toolId).sort() };
  }

  /** `GET /ai-tools`: every device of the workspace with its tools. */
  async list(tenantId: string) {
    const client = await this.tenants.getClient(tenantId);
    const hosts = await client.host.findMany({
      where: { status: { in: ['PENDING', 'APPROVED'] } },
      include: {
        tools: { where: { missing: false }, orderBy: { name: 'asc' } },
      },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });
    const now = Date.now();
    return {
      devices: hosts.map((h) => {
        const online =
          !!h.lastSeenAt && now - h.lastSeenAt.getTime() <= MONITORING_STALE_MS;
        return {
          hostId: h.id,
          hostname: h.hostname,
          os: h.os,
          status: h.status,
          online,
          lastSeenAt: h.lastSeenAt?.toISOString() ?? null,
          tools: h.tools.map((t) => ({
            toolId: t.toolId,
            name: t.name,
            version: t.version,
            path: t.path,
            protected: t.protected,
            protectMode: t.protectMode,
            desiredProtection: t.desiredProtection,
            changes: t.changes,
            supportedModes: hostTool(t.toolId)?.modes ?? [],
            enforcement: enforcementLabel(t.toolId, t, online),
          })),
        };
      }),
    };
  }

  /** `POST /ai-tools/:hostId/:toolId/protect|unprotect`: the owner's choice; the device applies it. */
  async setDesired(
    tenantId: string,
    hostId: string,
    toolId: string,
    desired: boolean,
    actor: AuditActor,
  ): Promise<{ toolId: string; desiredProtection: boolean }> {
    const client = await this.tenants.getClient(tenantId);
    const row = await client.hostTool.findUnique({
      where: { hostId_toolId: { hostId, toolId } },
    });
    // Tenant client: a host of another workspace has no row here.
    if (!row) throw new NotFoundException('Tool not found on this device');
    if (desired && (hostTool(toolId)?.modes.length ?? 0) === 0) {
      throw new BadRequestException(
        'This tool cannot be protected: Manar can only see it',
      );
    }
    await client.hostTool.update({
      where: { id: row.id },
      data: { desiredProtection: desired },
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: desired
        ? AUDIT_EVENT_TYPES.TOOL_PROTECTED
        : AUDIT_EVENT_TYPES.TOOL_UNPROTECTED,
      actor,
      data: { hostId, toolId, stage: 'requested' },
    });
    return { toolId, desiredProtection: desired };
  }
}
