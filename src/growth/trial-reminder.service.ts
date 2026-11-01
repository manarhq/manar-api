import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { ContactEmailService } from '../contact/contact-email.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { MailerService } from './mailer.service';
import { renderTrialReminder } from './trial-reminder';

const DAY_MS = 86_400_000;

/**
 * Seven days before the launch-offer free months end, once, to people who have not yet added a
 * card ("Keep Pro"). Claim-then-send like the weekly digest: the claim is given back on failure so
 * the next hourly tick retries.
 */
@Injectable()
export class TrialReminderService {
  private readonly logger = new Logger(TrialReminderService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly mailer: MailerService,
    private readonly contact: ContactEmailService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async sendDue(now = new Date()): Promise<{ sent: number; failed: number }> {
    const out = { sent: 0, failed: 0 };
    if (!this.mailer.configured) return out;
    const claims = await this.control.launchOfferClaim.findMany({
      where: {
        stripeSubscriptionId: { not: null },
        keptAt: null,
        reminderSentAt: null,
        trialEndsAt: { gt: now, lte: new Date(now.getTime() + 7 * DAY_MS) },
      },
      take: 500,
    });
    const web = (
      this.config.get('BILLING_CONSOLE_URL', { infer: true }) ?? ''
    ).replace(/\/+$/, '');
    for (const c of claims) {
      const won = await this.control.launchOfferClaim.updateMany({
        where: { id: c.id, reminderSentAt: null, keptAt: null },
        data: { reminderSentAt: now },
      });
      if (won.count !== 1) continue;
      try {
        const m = await this.control.membership.findUnique({
          where: {
            issuer_subject_tenantId: {
              issuer: c.issuer,
              subject: c.subject,
              tenantId: c.tenantId,
            },
          },
        });
        // The plan must still be this subscription (not cancelled or replaced since).
        const ent = await this.control.tenantEntitlement.findUnique({
          where: { tenantId: c.tenantId },
        });
        const to = await this.contact.verified(c.issuer, c.subject);
        if (
          !to ||
          !m ||
          m.status !== 'ACTIVE' ||
          ent?.stripeSubscriptionId !== c.stripeSubscriptionId
        )
          continue;
        const mail = renderTrialReminder({
          locale: m.locale === 'ar' ? 'ar' : 'en',
          endsAt: c.trialEndsAt!,
          link: `${web || 'https://manar.vax.sh'}/settings/billing`,
        });
        if (!(await this.mailer.send({ to, ...mail })))
          throw new Error('mail not accepted');
        out.sent++;
      } catch (error) {
        out.failed++;
        await this.control.launchOfferClaim.update({
          where: { id: c.id },
          data: { reminderSentAt: null },
        });
        this.logger.warn(`trial reminder failed for ${c.id}: ${String(error)}`);
      }
    }
    return out;
  }
}
