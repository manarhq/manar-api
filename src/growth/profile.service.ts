import { randomBytes } from 'node:crypto';
import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ReportCardService } from '../workspace/report-card.service';
import type { BadgeStats } from './badge.svg';
import { GrowthAuditService } from './growth-audit.service';

const SLUG = /^[A-Za-z0-9_-]{16}$/;
const STALE_MS = 60 * 60 * 1000;

/**
 * Opt-in public profile card and README badge. Public reads touch the control DB only: the
 * numbers are a snapshot taken when the owner switches it on, when they open the page, and at most
 * hourly when the badge is fetched. They are totals: no device, file, prompt, person or
 * workspace name.
 */
@Injectable()
export class ProfileService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly cards: ReportCardService,
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: GrowthAuditService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async get(tenantId: string) {
    const row = await this.control.publicProfile.findUnique({
      where: { tenantId },
    });
    return this.view(row);
  }

  async set(tenantId: string, enabled: boolean, userId: string) {
    const row = await this.control.publicProfile.upsert({
      where: { tenantId },
      create: {
        tenantId,
        slug: randomBytes(12).toString('base64url'),
        enabled,
      },
      update: { enabled },
    });
    if (enabled) await this.refresh(tenantId);
    await this.audit.record(
      tenantId,
      AUDIT_EVENT_TYPES.PROFILE_BADGE_CHANGED,
      { type: 'human', id: userId },
      { enabled },
    );
    return this.view({ ...row, enabled });
  }

  /** What the badge and card show. 404 for an unknown, malformed or switched-off slug. */
  async publicStats(
    slug: string,
  ): Promise<BadgeStats & { periodDays: number }> {
    if (!SLUG.test(slug)) throw new NotFoundException();
    const row = await this.control.publicProfile.findUnique({
      where: { slug },
    });
    if (!row?.enabled) throw new NotFoundException();
    let stats = row.stats as unknown as BadgeStats | null;
    if (
      !stats ||
      !row.statsAt ||
      Date.now() - row.statsAt.getTime() > STALE_MS
    ) {
      // Claim the refresh with a compare-and-set so a burst of fetches recomputes once.
      const claimed = await this.control.publicProfile.updateMany({
        where: { tenantId: row.tenantId, statsAt: row.statsAt },
        data: { statsAt: new Date() },
      });
      if (claimed.count === 1)
        stats = await this.refresh(row.tenantId).catch(() => stats);
    }
    return {
      ...(stats ?? { devices: 0, actions: 0, blocked: 0, secretsKeptSafe: 0 }),
      periodDays: 7,
    };
  }

  private async refresh(tenantId: string): Promise<BadgeStats> {
    const [card, client] = await Promise.all([
      this.cards.cardFor(tenantId),
      this.tenants.getClient(tenantId),
    ]);
    const stats: BadgeStats = {
      devices: await client.host.count({ where: { status: 'APPROVED' } }),
      actions: card.actions,
      blocked: card.blocked,
      secretsKeptSafe: card.secretsKeptSafe,
    };
    await this.control.publicProfile.update({
      where: { tenantId },
      data: { stats: stats as never, statsAt: new Date() },
    });
    return stats;
  }

  private view(row: { slug: string; enabled: boolean } | null) {
    const api = (
      this.config.get('MANAR_CONSOLE_URL', { infer: true }) ?? ''
    ).replace(/\/+$/, '');
    const web = (
      this.config.get('BILLING_CONSOLE_URL', { infer: true }) ?? ''
    ).replace(/\/+$/, '');
    if (!row?.enabled) return { enabled: false as const };
    const badgeUrl = `${api}/public/badge/${row.slug}.svg`;
    const profileUrl = `${web}/p/${row.slug}`;
    return {
      enabled: true as const,
      slug: row.slug,
      badgeUrl,
      profileUrl,
      markdown: `[![Protected by Manar](${badgeUrl})](${profileUrl})`,
    };
  }
}
