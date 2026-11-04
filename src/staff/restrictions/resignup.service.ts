import { randomInt } from 'node:crypto';
import { ForbiddenException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { VerifiedIdentity } from '../../auth/token-verifier.service';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import type { AppConfig } from '../../config/env.validation';
import { ControlPrismaService } from '../../database/control-prisma.service';
import type { StaffFingerprintKind } from '../../generated/control-client/client';
import { StaffAuditService } from '../audit/staff-audit.service';
import { fingerprint, normalizeEmail } from './fingerprints';
import { AccountSuspendedException } from './restriction-enforcement';

/** The device signal: the machine id, trimmed and lower-cased (same value the hosts table keys on). */
export const deviceFingerprintValue = (machineId: string) =>
  machineId.trim().toLowerCase();

const yymm = () => new Date().toISOString().slice(2, 7).replace('-', '');

/**
 * Re-signup checks (DESK spec §9.5): a new account, device or card that matches a fingerprint of
 * a restriction in force is blocked and recorded for review in Trust & Safety > Re-signup matches.
 * Fingerprints are keyed hashes; nothing readable is compared. A lookup failure fails closed.
 */
@Injectable()
export class ResignupService {
  private readonly logger = new Logger(ResignupService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly audit: StaffAuditService,
  ) {}

  private key(): string | null {
    return (
      this.config.get('RESTRICTION_FINGERPRINT_KEY', { infer: true }) ?? null
    );
  }

  /** The restriction in force holding one of these fingerprints, if any (not the caller's own). */
  private async match(
    signals: { kind: StaffFingerprintKind; valueHash: string }[],
    exceptAccountId?: string,
  ) {
    if (!signals.length) return null;
    try {
      for (const s of signals) {
        const hit = await this.control.staffRestrictionFingerprint.findFirst({
          where: {
            kind: s.kind,
            valueHash: s.valueHash,
            restriction: {
              kind: { in: ['SUSPEND', 'BAN'] },
              liftedAt: null,
              OR: [{ kind: 'BAN' }, { until: { gt: new Date() } }],
              ...(exceptAccountId
                ? { NOT: { accountId: exceptAccountId } }
                : {}),
            },
          },
          include: { restriction: true },
        });
        // A pair marked false positive never matches again.
        if (hit) {
          const cleared = await this.control.staffRestrictionMatch.findFirst({
            where: {
              kind: s.kind,
              matchedRestrictionId: hit.restrictionId,
              resolution: 'false_positive',
            },
          });
          if (!cleared) return { kind: s.kind, restriction: hit.restriction };
        }
      }
      return null;
    } catch (error) {
      throwFailClosed('restrictions', error);
    }
  }

  /**
   * Called when a person creates their first workspace: their verified email (email link) and their
   * Microsoft identity. A match bans the new account (`ban_evasion`, appealable) and refuses.
   */
  async checkNewAccount(id: VerifiedIdentity): Promise<void> {
    const key = this.key();
    if (!key || id.boundTenant) return;
    const signals: { kind: StaffFingerprintKind; valueHash: string }[] = [];
    const email = !id.idp && id.email ? normalizeEmail(id.email) : null;
    if (email)
      signals.push({
        kind: 'EMAIL',
        valueHash: fingerprint('EMAIL', email, key),
      });
    if (id.idp === 'microsoft' && id.tid && id.oid)
      signals.push({
        kind: 'IDP_IDENTITY',
        valueHash: fingerprint(
          'IDP_IDENTITY',
          `microsoft:${id.tid}:${id.oid}`,
          key,
        ),
      });
    const account = await this.control.account.upsert({
      where: { issuer_subject: { issuer: id.issuer, subject: id.subject } },
      create: {
        issuer: id.issuer,
        subject: id.subject,
        displayName: id.displayName ?? '',
        normalizedEmail: email,
        emailVerified: !id.idp,
        idp: id.idp ?? 'email',
      },
      update: {},
    });
    const hit = await this.match(signals, account.id);
    if (!hit) return;
    const ban = await this.control.$transaction(async (tx) => {
      const r = await tx.staffRestriction.create({
        data: {
          code: `RS-${yymm()}-${String(randomInt(100_000)).padStart(5, '0')}`,
          targetType: 'ACCOUNT',
          accountId: account.id,
          kind: 'BAN',
          category: 'ban_evasion',
          internalNote: `Re-signup matched the ${hit.kind.toLowerCase()} of restriction ${hit.restriction.code}.`,
          createdBy: 'system:resignup',
          fingerprints: { create: signals },
        },
      });
      await tx.staffRestrictionMatch.create({
        data: {
          kind: hit.kind,
          matchedRestrictionId: hit.restriction.id,
          newAccountId: account.id,
          action: 'blocked',
        },
      });
      await this.audit.append(
        {
          staffId: null,
          action: 'resignup.blocked',
          targetType: 'ACCOUNT',
          targetId: account.id,
          data: { kind: hit.kind, matched: hit.restriction.code },
        },
        tx,
      );
      return r;
    });
    throw new AccountSuspendedException(
      { id: ban.id, kind: 'BAN', category: 'ban_evasion', until: null },
      new Date(),
    );
  }

  /** Before a device certificate is issued, in every workspace (AC-26). */
  async checkDevice(machineId: string, tenantId: string): Promise<void> {
    const key = this.key();
    if (!key) return;
    const hit = await this.match([
      {
        kind: 'DEVICE',
        valueHash: fingerprint(
          'DEVICE',
          deviceFingerprintValue(machineId),
          key,
        ),
      },
    ]);
    if (!hit) return;
    // The device's own restricted owner re-installing in the same personal workspace is still blocked.
    await this.control.staffRestrictionMatch.create({
      data: {
        kind: 'DEVICE',
        matchedRestrictionId: hit.restriction.id,
        newTenantId: tenantId,
        action: 'blocked',
      },
    });
    await this.audit.append({
      staffId: null,
      action: 'resignup.device_blocked',
      targetType: 'TENANT',
      targetId: tenantId,
      data: { matched: hit.restriction.code },
    });
    throw new ForbiddenException({
      statusCode: 403,
      code: 'device_blocked',
      message: "This device can't be added. Contact support@fixio.ae.",
    });
  }

  /**
   * A card attached in Stripe: a match bans the paying workspace's owner (`ban_evasion`) and is
   * recorded; the caller cancels the subscription. Returns the matched restriction code, or null.
   */
  async checkCard(
    cardFingerprint: string,
    tenantId: string,
  ): Promise<string | null> {
    const key = this.key();
    if (!key) return null;
    const hit = await this.match([
      { kind: 'CARD', valueHash: fingerprint('CARD', cardFingerprint, key) },
    ]);
    if (!hit) return null;
    const owner = await this.control.membership.findFirst({
      where: { tenantId, role: 'TENANT_OWNER', status: 'ACTIVE' },
      orderBy: { createdAt: 'asc' },
    });
    const account = owner
      ? await this.control.account.upsert({
          where: {
            issuer_subject: { issuer: owner.issuer, subject: owner.subject },
          },
          create: {
            issuer: owner.issuer,
            subject: owner.subject,
            displayName: owner.displayName ?? '',
            normalizedEmail: owner.email ? normalizeEmail(owner.email) : null,
          },
          update: {},
        })
      : null;
    await this.control.$transaction(async (tx) => {
      if (account && account.id !== hit.restriction.accountId)
        await tx.staffRestriction.create({
          data: {
            code: `RS-${yymm()}-${String(randomInt(100_000)).padStart(5, '0')}`,
            targetType: 'ACCOUNT',
            accountId: account.id,
            kind: 'BAN',
            category: 'ban_evasion',
            internalNote: `Card matched restriction ${hit.restriction.code}.`,
            createdBy: 'system:resignup',
            fingerprints: {
              create: [
                {
                  kind: 'CARD',
                  valueHash: fingerprint('CARD', cardFingerprint, key),
                },
              ],
            },
          },
        });
      await tx.staffRestrictionMatch.create({
        data: {
          kind: 'CARD',
          matchedRestrictionId: hit.restriction.id,
          newAccountId: account?.id,
          newTenantId: tenantId,
          action: 'blocked',
        },
      });
      await this.audit.append(
        {
          staffId: null,
          action: 'resignup.card_blocked',
          targetType: 'TENANT',
          targetId: tenantId,
          data: { matched: hit.restriction.code },
        },
        tx,
      );
    });
    return hit.restriction.code;
  }
}
