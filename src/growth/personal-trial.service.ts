import { createHash } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { renderTrialReminder } from '../billing/billing-mail';
import { EntitlementsService } from '../billing/entitlements.service';
import { PERSONAL_TRIAL_DAYS } from '../billing/plans';
import type { AppConfig } from '../config/env.validation';
import {
  ContactEmailService,
  isPlaceholderEmail,
} from '../contact/contact-email.service';
import { ControlPrismaService } from '../database/control-prisma.service';
import { DEVICES_DEFAULTS } from '../devices/devices.config';
import { ReportCardService } from '../workspace/report-card.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { isConsumerDomain, isDisposableDomain } from './disposable';
import { MailerService } from './mailer.service';

const DAY_MS = 86_400_000;
/** Claims per day from one (non-consumer) email domain, and from one IP address. */
const DOMAIN_DAILY_CAP = 3;
const IP_DAILY_CAP = 5;
/** Reminder days, counted from the start (day 14 is the last day). */
export const REMINDER_DAYS = [10, 13, 14] as const;

// Same inputs as the retired launch offer, so its claims (copied into trial_claims) still match.
const sha = (prefix: string, v: string) =>
  createHash('sha256').update(`${prefix}${v}`).digest('hex');
export const deviceHash = (machineId: string) =>
  sha('manar-launch-device:', machineId);

export interface DeviceFacts {
  machineId: string;
  /** TPM endorsement key fingerprint, when the device attested one. */
  ekFingerprint?: string | null;
  ip?: string | null;
}

/**
 * The 14-day personal trial (workspace spec 2026-11-04-payg, 7.1). It starts when a new personal
 * workspace's first device is approved, needs no card and touches no Stripe object. It unlocks
 * only "up to 3 devices" and reads as Free after its end. Given once per person, email, device
 * and TPM key: the claim is written under one advisory lock and unique indexes back it up.
 */
@Injectable()
export class PersonalTrialService {
  private readonly logger = new Logger(PersonalTrialService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly entitlements: EntitlementsService,
    private readonly contact: ContactEmailService,
    private readonly mailer: MailerService,
    private readonly cards: ReportCardService,
    private readonly tenants: TenantDatabaseManager,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  /** Called after a device was registered and approved. Never throws: it cannot fail an install. */
  async onDeviceRegistered(
    tenantId: string,
    device: DeviceFacts,
  ): Promise<boolean> {
    try {
      return await this.claim(tenantId, device);
    } catch (error) {
      this.logger.error(`trial claim failed for ${tenantId}: ${String(error)}`);
      return false;
    }
  }

  async claim(
    tenantId: string,
    device: DeviceFacts,
    now = new Date(),
  ): Promise<boolean> {
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
    });
    if (
      !tenant ||
      tenant.kind !== 'PERSONAL' ||
      tenant.status !== 'ACTIVE' ||
      !tenant.ownerIssuer ||
      !tenant.ownerSubject
    )
      return false;
    // Only a workspace that never had a plan or a trial.
    const current = await this.control.tenantEntitlement.findUnique({
      where: { tenantId },
    });
    if (current && (current.plan !== 'free' || current.trialEndsAt))
      return false;

    const issuer = tenant.ownerIssuer;
    const subject = tenant.ownerSubject;
    // A Microsoft or GitHub account is a real identity; an email-link account needs a verified
    // email on a domain that is not a throwaway mailbox service.
    const [idp, email] = await Promise.all([
      this.contact.idpOf(issuer, subject),
      this.contact.verified(issuer, subject),
    ]);
    const address =
      email && !isPlaceholderEmail(email) ? email.toLowerCase() : null;
    const domain = address ? address.split('@')[1]! : null;
    const strong = idp === 'microsoft' || idp === 'github';
    if (domain && isDisposableDomain(domain)) return false;
    if (!strong && !domain) return false;

    const dev = deviceHash(device.machineId);
    const ek = device.ekFingerprint
      ? sha('manar-launch-ek:', device.ekFingerprint)
      : null;
    const ipHash = device.ip ? sha('manar-launch-ip:', device.ip) : null;
    const emailHash = address ? sha('manar-trial-email:', address) : null;
    const since = new Date(now.getTime() - DAY_MS);
    const claim = await this.control.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('personal-trial'))`;
      const taken = await tx.trialClaim.findFirst({
        where: {
          OR: [
            { issuer, subject, kind: 'personal' },
            { deviceHash: dev },
            { tenantId },
            ...(ek ? [{ ekHash: ek }] : []),
            ...(emailHash ? [{ emailHash }] : []),
          ],
        },
      });
      if (taken) return null;
      if (domain && !isConsumerDomain(domain)) {
        const n = await tx.trialClaim.count({
          where: { emailDomain: domain, claimedAt: { gt: since } },
        });
        if (n >= DOMAIN_DAILY_CAP) return null;
      }
      if (ipHash) {
        const n = await tx.trialClaim.count({
          where: { ipHash, claimedAt: { gt: since } },
        });
        if (n >= IP_DAILY_CAP) return null;
      }
      return tx.trialClaim.create({
        data: {
          tenantId,
          kind: 'personal',
          issuer,
          subject,
          emailHash,
          emailDomain: domain,
          deviceHash: dev,
          ekHash: ek,
          ipHash,
          claimedAt: now,
        },
      });
    });
    if (!claim) return false;
    await this.entitlements.change(
      tenantId,
      {
        plan: 'trial',
        status: 'active',
        trialEndsAt: new Date(now.getTime() + PERSONAL_TRIAL_DAYS * DAY_MS),
      },
      { type: 'system', id: 'personal-trial' },
      'trial',
    );
    return true;
  }

  /**
   * Hourly: the day 10, 13 and 14 reminders, in the person's language, with what Manar blocked
   * in the trial. Claim-then-send: a failed send gives the day back for the next tick.
   */
  async sendDue(now = new Date()): Promise<{ sent: number; failed: number }> {
    const out = { sent: 0, failed: 0 };
    if (!this.mailer.configured) return out;
    const claims = await this.control.trialClaim.findMany({
      where: {
        kind: 'personal',
        claimedAt: {
          gt: new Date(now.getTime() - PERSONAL_TRIAL_DAYS * DAY_MS),
        },
      },
      take: 1000,
    });
    for (const c of claims) {
      const day =
        Math.floor((now.getTime() - c.claimedAt.getTime()) / DAY_MS) + 1;
      const due = REMINDER_DAYS.filter(
        (d) => d <= day && !c.remindersSent.includes(d),
      );
      if (!due.length) continue;
      const d = due[due.length - 1]!;
      // Claim the day (and any earlier missed day, so a late tick sends one email, not three).
      const won = await this.control.$executeRaw`
        UPDATE "trial_claims" SET "remindersSent" = "remindersSent" || ${due}::int[]
        WHERE "id" = ${c.id} AND NOT (${d} = ANY("remindersSent"))`;
      if (won !== 1) continue;
      try {
        if (await this.remind(c, d, now)) out.sent++;
      } catch (error) {
        out.failed++;
        await this.control.trialClaim.update({
          where: { id: c.id },
          data: { remindersSent: c.remindersSent },
        });
        this.logger.warn(`trial reminder failed for ${c.id}: ${String(error)}`);
      }
    }
    return out;
  }

  private async remind(
    c: { tenantId: string; issuer: string; subject: string },
    day: number,
    now: Date,
  ): Promise<boolean> {
    // Still on the trial (not upgraded, not ended early)?
    const e = await this.entitlements.get(c.tenantId);
    if (e.plan !== 'trial') return false;
    const m = await this.control.membership.findUnique({
      where: {
        issuer_subject_tenantId: {
          issuer: c.issuer,
          subject: c.subject,
          tenantId: c.tenantId,
        },
      },
    });
    const to = await this.contact.verified(c.issuer, c.subject);
    if (!to || !m || m.status !== 'ACTIVE') return false;
    const locale = m.locale === 'ar' ? 'ar' : 'en';
    const client = await this.tenants.getClient(c.tenantId);
    const [a, b] = await Promise.all([
      this.cards.compute(client, now),
      this.cards.compute(client, new Date(now.getTime() - 7 * DAY_MS)),
    ]);
    const web = (
      this.config.get('BILLING_CONSOLE_URL', { infer: true }) ??
      DEVICES_DEFAULTS.MANAR_CONSOLE_URL
    ).replace(/\/+$/, '');
    const mail = renderTrialReminder({
      locale,
      daysLeft: PERSONAL_TRIAL_DAYS - day,
      blocked: a.blocked + b.blocked,
      link: `${web}/${locale}/settings/billing`,
    });
    if (!(await this.mailer.send({ to, ...mail })))
      throw new Error('mail not accepted');
    return true;
  }
}
