import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { DEVICES_DEFAULTS } from '../devices/devices.config';
import { ControlPrismaService } from '../database/control-prisma.service';
import { ContactEmailService } from '../contact/contact-email.service';
import { ReportCardService } from '../workspace/report-card.service';
import { DEFAULT_TZ, dueNow, renderDigest } from './digest';
import { growthSetting } from './growth.config';
import { MailerService } from './mailer.service';
import { signToken } from './signed-token';

/**
 * "Your AI week", sent by the hourly Temporal schedule. A person gets it once a week, Monday
 * 08:00 their time (default Asia/Dubai). Each send is claimed first (`digestSentWeek`) so two
 * workers cannot both send; a failed send gives the claim back so the next hour retries until noon.
 * Weeks with no AI activity send nothing (an empty email to someone who never installed is spam).
 */
@Injectable()
export class DigestService {
  private readonly logger = new Logger(DigestService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly cards: ReportCardService,
    private readonly mailer: MailerService,
    private readonly contact: ContactEmailService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  unsubscribeUrl(membershipId: string): string | null {
    const secret = this.config.get('MANAR_LINK_SECRET', { infer: true });
    const api = this.config.get('MANAR_CONSOLE_URL', { infer: true });
    if (!secret || !api) return null;
    const token = signToken(secret, 'unsubscribe', membershipId, null);
    return `${api.replace(/\/+$/, '')}/public/unsubscribe/${token}`;
  }

  async sendDue(
    now = new Date(),
  ): Promise<{ sent: number; skipped: number; failed: number }> {
    const out = { sent: 0, skipped: 0, failed: 0 };
    if (
      growthSetting(this.config, 'WEEKLY_DIGEST_ENABLED') !== 'true' ||
      !this.mailer.configured
    )
      return out;
    // Only the zones in use, then only those where it is Monday morning right now.
    const zones = await this.control.membership.groupBy({
      by: ['timezone'],
      where: { weeklyDigest: true, status: 'ACTIVE' },
    });
    const dueZones = zones.filter((z) => dueNow(now, z.timezone).due);
    for (const z of dueZones) {
      const { week } = dueNow(now, z.timezone);
      const rows = await this.control.membership.findMany({
        where: {
          timezone: z.timezone,
          weeklyDigest: true,
          status: 'ACTIVE',
          role: 'TENANT_OWNER',
          OR: [{ digestSentWeek: null }, { digestSentWeek: { not: week } }],
          tenant: { kind: 'PERSONAL', status: 'ACTIVE' },
        },
        take: 5_000, // ponytail: one pass per hour; page it if a single zone ever holds more
      });
      // Mail goes to the verified contact email only; nobody without one is claimed or mailed.
      const emails = await this.contact.verifiedMany(rows);
      for (const m of rows) {
        const to = emails.get(`${m.issuer}\n${m.subject}`);
        if (!to) continue;
        const claimed = await this.control.membership.updateMany({
          where: {
            id: m.id,
            OR: [{ digestSentWeek: null }, { digestSentWeek: { not: week } }],
          },
          data: { digestSentWeek: week },
        });
        if (claimed.count !== 1) continue;
        try {
          if (!(await this.sendOne(m, to, week))) out.skipped++;
          else out.sent++;
        } catch (error) {
          out.failed++;
          await this.control.membership.update({
            where: { id: m.id },
            data: { digestSentWeek: m.digestSentWeek },
          });
          this.logger.warn(
            `digest failed for membership ${m.id}: ${String(error)}`,
          );
        }
      }
    }
    this.logger.log(
      `Weekly digest: ${out.sent} sent, ${out.skipped} skipped, ${out.failed} failed`,
    );
    return out;
  }

  private async sendOne(
    m: {
      id: string;
      tenantId: string;
      locale: string | null;
    },
    to: string,
    week: string,
  ): Promise<boolean> {
    const unsub = this.unsubscribeUrl(m.id);
    if (!unsub) return false;
    const totals = await this.cards.refresh(m.tenantId);
    if (totals.actions === 0) return false;
    const web = (
      this.config.get('BILLING_CONSOLE_URL', { infer: true }) ?? ''
    ).replace(/\/+$/, '');
    const mail = renderDigest({
      locale: m.locale === 'ar' ? 'ar' : 'en',
      totals,
      consoleUrl: web || DEVICES_DEFAULTS.MANAR_CONSOLE_URL,
      unsubscribeUrl: unsub,
    });
    const ok = await this.mailer.send({
      to,
      ...mail,
      headers: {
        'List-Unsubscribe': `<${unsub}>`,
        'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click',
      },
    });
    if (!ok) throw new Error(`mail not accepted for ${week}`);
    return true;
  }

  /** One-click unsubscribe: the signed token names the membership. Idempotent. */
  async unsubscribe(membershipId: string): Promise<boolean> {
    const r = await this.control.membership.updateMany({
      where: { id: membershipId },
      data: { weeklyDigest: false },
    });
    return r.count === 1;
  }
}

export { DEFAULT_TZ };
