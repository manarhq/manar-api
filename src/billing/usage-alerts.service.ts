import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { ContactEmailService } from '../contact/contact-email.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { DEVICES_DEFAULTS } from '../devices/devices.config';
import { MailerService } from '../growth/mailer.service';
import { renderUsageAlert } from './billing-mail';
import { EntitlementsService } from './entitlements.service';
import { monthOf } from './plans';
import { allowanceFor, balanceOf, defaultCap } from './usage-meter.service';
import { thresholdKeys } from './wallet.service';

/**
 * Hourly: emails the owners of a workspace once per alert key per month (50/80/100% of the
 * allowance and of the cap, low credits). The key is claimed in `usage_months.alertsSent` before
 * sending and given back if the send fails, so a repeated tick never sends twice.
 */
@Injectable()
export class UsageAlertsService {
  private readonly logger = new Logger(UsageAlertsService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
    private readonly mailer: MailerService,
    private readonly contact: ContactEmailService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async sendDue(now = new Date()): Promise<{ sent: number; failed: number }> {
    const out = { sent: 0, failed: 0 };
    if (!this.mailer.configured) return out;
    const month = monthOf(now);
    const months = await this.control.usageMonth.findMany({
      where: { month },
      take: 2000,
    });
    for (const m of months) {
      try {
        const e = await this.entitlements.get(m.tenantId);
        const wallet = await this.control.creditWallet.findUnique({
          where: { tenantId: m.tenantId },
        });
        // ponytail: the pool uses 0 seats here (the minimum of 3); exact seats would need the tick.
        const keys = thresholdKeys({
          aiUsed: m.aiUsed,
          minutesUsed: m.minutesUsed,
          creditsSpent: m.creditsSpent,
          aiIncluded: allowanceFor(e, 'ai', 0),
          minutesIncluded: allowanceFor(e, 'cloud_minute', 0),
          cap: wallet ? wallet.capCredits : defaultCap(e.plan),
          balance: await balanceOf(this.control, m.tenantId, now),
          autoTopUp: wallet?.autoTopUp ?? false,
        }).filter((k) => !m.alertsSent.includes(k));
        // Only the highest new step per kind: crossing 50 and 80 in one hour sends one email.
        for (const key of highestPerKind(keys)) {
          const ok = await this.claim(m.tenantId, month, key);
          if (!ok) continue;
          try {
            out.sent += await this.notifyOwners(m.tenantId, key);
          } catch (error) {
            out.failed++;
            await this.release(m.tenantId, month, key);
            throw error;
          }
        }
        // Lower steps that were skipped are recorded so they never send later.
        for (const key of keys)
          if (!highestPerKind(keys).includes(key))
            await this.claim(m.tenantId, month, key);
      } catch (error) {
        this.logger.warn(
          `usage alerts failed for tenant "${m.tenantId}": ${String(error)}`,
        );
      }
    }
    return out;
  }

  private async claim(tenantId: string, month: string, key: string) {
    const n = await this.control.$executeRaw`
      UPDATE "usage_months" SET "alertsSent" = array_append("alertsSent", ${key})
      WHERE "tenantId" = ${tenantId} AND "month" = ${month}
        AND NOT (${key} = ANY("alertsSent"))`;
    return n === 1;
  }

  private async release(tenantId: string, month: string, key: string) {
    await this.control.$executeRaw`
      UPDATE "usage_months" SET "alertsSent" = array_remove("alertsSent", ${key})
      WHERE "tenantId" = ${tenantId} AND "month" = ${month}`;
  }

  /** Owners of the workspace, each in their own language. Returns emails accepted. */
  private async notifyOwners(tenantId: string, key: string): Promise<number> {
    const owners = await this.control.membership.findMany({
      where: {
        tenantId,
        status: 'ACTIVE',
        OR: [{ role: 'TENANT_OWNER' }, { extraRoles: { has: 'TENANT_OWNER' } }],
      },
    });
    const web = (
      this.config.get('BILLING_CONSOLE_URL', { infer: true }) ??
      DEVICES_DEFAULTS.MANAR_CONSOLE_URL
    ).replace(/\/+$/, '');
    let sent = 0;
    for (const o of owners) {
      const to = await this.contact.verified(o.issuer, o.subject);
      if (!to) continue;
      const locale = o.locale === 'ar' ? 'ar' : 'en';
      const mail = renderUsageAlert({
        locale,
        key,
        link: `${web}/${locale}/settings/billing`,
      });
      if (!(await this.mailer.send({ to, ...mail })))
        throw new Error('mail not accepted');
      sent++;
    }
    return sent;
  }
}

/** `["ai:50","ai:80","cap:50"]` -> `["ai:80","cap:50"]`. */
export function highestPerKind(keys: string[]): string[] {
  const best = new Map<string, string>();
  for (const k of keys) {
    const [name, p] = k.split(':') as [string, string];
    const prev = best.get(name);
    if (!prev || Number(p) > Number(prev.split(':')[1])) best.set(name, k);
  }
  return [...best.values()];
}
