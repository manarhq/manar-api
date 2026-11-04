import { ForbiddenException, Injectable } from '@nestjs/common';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import { ControlPrismaService } from '../../database/control-prisma.service';

export const ACCOUNT_SUSPENDED = 'account_suspended';
const APPEAL_EVERY_MS = 24 * 3_600_000;

export interface ActiveRestriction {
  id: string;
  kind: 'SUSPEND' | 'BAN';
  category: string;
  until: Date | null;
}

/** 403 `account_suspended` with what the customer may see: category, end time, next appeal time. */
export class AccountSuspendedException extends ForbiddenException {
  constructor(r: ActiveRestriction, appealAvailableAt: Date | null) {
    super({
      code: ACCOUNT_SUSPENDED,
      message:
        r.kind === 'BAN'
          ? 'Your Manar account was banned. You can see why and appeal at your console.'
          : 'Your Manar account is suspended. You can see why and appeal at your console.',
      kind: r.kind,
      category: r.category,
      until: r.until,
      appealAvailableAt,
    });
  }
}

/**
 * The one restriction lookup every customer path goes through (TokenVerifierService, HostAuthGuard):
 * one indexed query, read-time expiry (spec §9.1), no cache. A failure is 503
 * `enforcement_dependency_unavailable`, never a pass.
 */
@Injectable()
export class RestrictionEnforcement {
  constructor(private readonly control: ControlPrismaService) {}

  async activeFor(
    issuer: string,
    subject: string,
  ): Promise<ActiveRestriction | null> {
    try {
      const rows = await this.control.$queryRaw<ActiveRestriction[]>`
        SELECT r.id, r.kind::text AS kind, r.category, r.until
        FROM staff_restrictions r JOIN accounts a ON a.id = r."accountId"
        WHERE a.issuer = ${issuer} AND a.subject = ${subject}
          AND r.kind IN ('SUSPEND', 'BAN') AND r."liftedAt" IS NULL AND r."startsAt" <= now()
          AND (r.kind = 'BAN' OR r.until > now())
        ORDER BY (r.kind = 'BAN') DESC, r.until DESC NULLS FIRST
        LIMIT 1`;
      return rows[0] ?? null;
    } catch (error) {
      throwFailClosed('restrictions', error);
    }
  }

  async refuseIfRestricted(issuer: string, subject: string): Promise<void> {
    const r = await this.activeFor(issuer, subject);
    if (!r) return;
    const last = await this.control.staffAppeal
      .findFirst({
        where: { restrictionId: r.id },
        orderBy: { submittedAt: 'desc' },
        select: { submittedAt: true },
      })
      .catch(() => null);
    throw new AccountSuspendedException(
      r,
      last
        ? new Date(last.submittedAt.getTime() + APPEAL_EVERY_MS)
        : new Date(),
    );
  }
}
