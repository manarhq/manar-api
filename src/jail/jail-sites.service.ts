import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { z } from 'zod';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import {
  isJailTool,
  jailFlags,
  JAIL_TOOL_IDS,
  normalizeRuleSite,
  ruleLive,
  siteCovers,
  type SiteMode,
} from './jail-sites';

export const SiteRuleInputSchema = z.object({
  hostId: z.string().min(1).max(128),
  toolId: z.string().min(1).max(128),
  site: z.string().min(1).max(260),
  mode: z.enum(['ALLOW', 'DENY']),
  /** Hours the rule lasts; omitted means always. */
  hours: z
    .number()
    .int()
    .min(1)
    .max(24 * 365)
    .optional(),
});
export type SiteRuleInput = z.infer<typeof SiteRuleInputSchema>;

/** Creates or replaces the rule for (host, tool, site). Used by the console and by an approval. */
export function upsertSiteRule(
  client: Pick<TenantPrismaClient, 'hostSiteRule'>,
  input: {
    hostId: string;
    toolId: string;
    site: string;
    mode: SiteMode;
    expiresAt: Date | null;
    source: 'approval' | 'console';
    createdBy: string;
  },
) {
  const data = {
    mode: input.mode,
    expiresAt: input.expiresAt,
    source: input.source,
    createdBy: input.createdBy,
    createdAt: new Date(),
  };
  return client.hostSiteRule.upsert({
    where: {
      hostId_toolId_site: {
        hostId: input.hostId,
        toolId: input.toolId,
        site: input.site,
      },
    },
    create: {
      hostId: input.hostId,
      toolId: input.toolId,
      site: input.site,
      ...data,
    },
    update: data,
  });
}

/**
 * True when an answer to a prompt must not be remembered: a person's DENY covers the site, or a
 * rule made by hand in the console already exists for exactly this site. The approval then applies
 * once only.
 */
export async function siteRuleBlocksRemember(
  client: Pick<TenantPrismaClient, 'hostSiteRule'>,
  hostId: string,
  toolId: string,
  site: string,
  now = new Date(),
) {
  const rows = await client.hostSiteRule.findMany({
    where: { hostId, toolId },
    take: 1000,
  });
  return rows.some(
    (r) =>
      ruleLive(r, now) &&
      ((r.mode === 'DENY' && siteCovers(r.site, site)) ||
        (r.site === site && r.source === 'console')),
  );
}

@Injectable()
export class JailSitesService {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  /** The `jail` part of `GET /host/v1/config`. Tenant and host come from the certificate. */
  async config(host: { hostId: string; tenantId: string }, now = new Date()) {
    const flags = jailFlags();
    if (!flags.enabled)
      return { enabled: false, windows: false, tools: [], rules: [] };
    const client = await this.tenants.getClient(host.tenantId);
    const [tools, rules] = await Promise.all([
      client.hostTool.findMany({
        where: {
          hostId: host.hostId,
          toolId: { in: [...JAIL_TOOL_IDS] },
          desiredProtection: true,
          missing: false,
        },
        select: { toolId: true },
      }),
      client.hostSiteRule.findMany({
        where: {
          hostId: host.hostId,
          OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
        },
        orderBy: { createdAt: 'asc' },
        take: 1000,
      }),
    ]);
    return {
      enabled: true,
      windows: flags.windows,
      tools: tools.map((t) => t.toolId).sort(),
      rules: rules.map((r) => ({
        toolId: r.toolId,
        site: r.site,
        mode: r.mode,
        expiresAt: r.expiresAt,
      })),
    };
  }

  /**
   * The live rule that answers an ask without a prompt. A wildcard rule covers the site too, and a
   * DENY (exact or wildcard) always wins over an ALLOW.
   */
  async findLive(
    client: Pick<TenantPrismaClient, 'hostSiteRule'>,
    hostId: string,
    toolId: string,
    site: string,
    now = new Date(),
  ) {
    const rows = await client.hostSiteRule.findMany({
      where: { hostId, toolId },
      take: 1000,
    });
    const hits = rows.filter(
      (r) => ruleLive(r, now) && siteCovers(r.site, site),
    );
    return hits.find((r) => r.mode === 'DENY') ?? hits[0] ?? null;
  }

  async list(tenantId: string, hostId?: string, now = new Date()) {
    const client = await this.tenants.getClient(tenantId);
    const rows = await client.hostSiteRule.findMany({
      where: {
        ...(hostId ? { hostId } : {}),
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      include: { host: { select: { hostname: true } } },
      orderBy: [{ hostId: 'asc' }, { toolId: 'asc' }, { site: 'asc' }],
      take: 500,
    });
    return {
      items: rows.map((r) => ({
        id: r.id,
        hostId: r.hostId,
        hostname: r.host.hostname,
        toolId: r.toolId,
        site: r.site,
        mode: r.mode,
        expiresAt: r.expiresAt,
        source: r.source,
        createdBy: r.createdBy,
        createdAt: r.createdAt,
      })),
    };
  }

  async create(
    tenantId: string,
    input: SiteRuleInput,
    actor: { type: 'human'; id: string },
    now = new Date(),
  ) {
    const site = normalizeRuleSite(input.site);
    if (!site) throw new BadRequestException('not a valid site');
    if (!isJailTool(input.toolId))
      throw new BadRequestException('this tool is not filtered');
    const client = await this.tenants.getClient(tenantId);
    const host = await client.host.findUnique({ where: { id: input.hostId } });
    if (!host) throw new NotFoundException('no such device');
    const row = await upsertSiteRule(client, {
      hostId: host.id,
      toolId: input.toolId,
      site,
      mode: input.mode,
      expiresAt: input.hours
        ? new Date(now.getTime() + input.hours * 3_600_000)
        : null,
      source: 'console',
      createdBy: actor.id,
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.JAIL_SITE_RULE_CREATED,
      actor,
      data: {
        hostId: host.id,
        toolId: row.toolId,
        site,
        mode: row.mode,
        via: 'console',
      },
    });
    return { id: row.id };
  }

  async remove(
    tenantId: string,
    id: string,
    actor: { type: 'human'; id: string },
  ) {
    const client = await this.tenants.getClient(tenantId);
    const row = await client.hostSiteRule.findUnique({ where: { id } });
    if (!row) throw new NotFoundException('no such rule');
    await client.hostSiteRule.delete({ where: { id } });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.JAIL_SITE_RULE_REMOVED,
      actor,
      data: {
        hostId: row.hostId,
        toolId: row.toolId,
        site: row.site,
        mode: row.mode,
      },
    });
    return { removed: true };
  }
}
