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

  /**
   * The restriction in force holding one of these fingerprints, if any (not the subject's own).
   * A false-positive clearance applies only to the exact (subject, fingerprint, restriction) it
   * was recorded for (security review, 4 Nov): a later account with the same signal is checked again.
   */
  private async match(
    signals: { kind: StaffFingerprintKind; valueHash: string }[],
    subject: { accountId?: string; tenantId?: string },
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
              ...(subject.accountId
                ? { NOT: { accountId: subject.accountId } }
                : {}),
            },
          },
          include: { restriction: true },
        });
        if (!hit) continue;
        const cleared = await this.control.staffRestrictionMatch.findFirst({
          where: {
            kind: s.kind,
            valueHash: s.valueHash,
            matchedRestrictionId: hit.restrictionId,
            resolution: 'false_positive',
            ...(subject.accountId
              ? { newAccountId: subject.accountId }
              : { newTenantId: subject.tenantId ?? '' }),
          },
        });
        if (!cleared)
          return {
            kind: s.kind,
            valueHash: s.valueHash,
            restriction: hit.restriction,
          };
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
    const hit = await this.match(signals, { accountId: account.id });
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
          valueHash: hit.valueHash,
          matchedRestrictionId: hit.restriction.id,
          newAccountId: account.id,
          createdRestrictionId: r.id,
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
  /**
   * Before a device certificate is issued, in every workspace (AC-26). Only attested identifiers
   * count (security review, 4 Nov): the key the device enrols with and, when TPM attestation
   * passed, its endorsement key. The machine id is self-reported and is never a signal.
   */
  async checkDevice(
    device: { keyFingerprint: string; tpmEk?: string | null },
    tenantId: string,
  ): Promise<void> {
    const key = this.key();
    if (!key) return;
    const signals: { kind: StaffFingerprintKind; valueHash: string }[] = [
      {
        kind: 'DEVICE',
        valueHash: fingerprint('DEVICE', device.keyFingerprint, key),
      },
      ...(device.tpmEk
        ? [
            {
              kind: 'TPM_EK' as const,
              valueHash: fingerprint('TPM_EK', device.tpmEk, key),
            },
          ]
        : []),
    ];
    const hit = await this.match(signals, { tenantId });
    if (!hit) return;
    // The device's own restricted owner re-installing in the same personal workspace is still blocked.
    await this.control.staffRestrictionMatch.create({
      data: {
        kind: hit.kind,
        valueHash: hit.valueHash,
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
    const hit = await this.match(
      [{ kind: 'CARD', valueHash: fingerprint('CARD', cardFingerprint, key) }],
      { tenantId },
    );
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
      const created =
        account && account.id !== hit.restriction.accountId
          ? await tx.staffRestriction.create({
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
            })
          : null;
      await tx.staffRestrictionMatch.create({
        data: {
          kind: 'CARD',
          valueHash: hit.valueHash,
          createdRestrictionId: created?.id ?? null,
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
