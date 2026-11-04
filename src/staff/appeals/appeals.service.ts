import { randomInt } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../../config/env.validation';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { StaffAuditService } from '../audit/staff-audit.service';
import { RestrictionEnforcement } from '../restrictions/restriction-enforcement';
import { dueAt } from '../restrictions/restriction-rules';

export const APPEAL_EVERY_MS = 24 * 3_600_000;
export const MAX_APPEAL = 2000;
const TURNSTILE_URL =
  'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const CODE = '23456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * The customer side of a restriction (DESK spec §9.4): what they may see (kind, category, end time,
 * next appeal time; never the internal note) and the appeal itself: Turnstile checked server side,
 * one per account per 24 hours counted from the database (holds across replicas), due in 3
 * business days. In Phase 1 the appeal row is the ticket (AC-24).
 */
@Injectable()
export class AppealsService {
  private readonly logger = new Logger(AppealsService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly enforcement: RestrictionEnforcement,
    private readonly config: ConfigService<AppConfig, true>,
    private readonly audit: StaffAuditService,
  ) {}

  async restrictionOf(issuer: string, subject: string) {
    const r = await this.enforcement.activeFor(issuer, subject);
    if (!r) return { restricted: false as const };
    const last = await this.control.staffAppeal.findFirst({
      where: { restrictionId: r.id },
      orderBy: { submittedAt: 'desc' },
    });
    return {
      restricted: true as const,
      kind: r.kind,
      category: r.category,
      until: r.until,
      appealAvailableAt: last
        ? new Date(last.submittedAt.getTime() + APPEAL_EVERY_MS)
        : new Date(),
      appeal: last
        ? {
            code: last.code,
            status: last.status,
            submittedAt: last.submittedAt,
            dueAt: last.dueAt,
          }
        : null,
    };
  }

  async submit(
    issuer: string,
    subject: string,
    input: { text: string; turnstileToken: string; ip?: string },
  ) {
    const text = input.text.trim();
    if (!text || text.length > MAX_APPEAL)
      throw new BadRequestException({
        code: 'invalid_request',
        message: `Write your appeal in up to ${MAX_APPEAL} characters.`,
      });
    const r = await this.enforcement.activeFor(issuer, subject);
    if (!r)
      throw new NotFoundException({
        code: 'not_restricted',
        message: 'Your account has no restriction to appeal.',
      });
    await this.verifyTurnstile(input.turnstileToken, input.ip);
    const account = await this.control.account.findUniqueOrThrow({
      where: { issuer_subject: { issuer, subject } },
    });
    return this.control.$transaction(async (tx) => {
      // Serialise this account's appeals so the 24-hour rule holds under concurrent submits.
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`appeal:${account.id}`}))`;
      const last = await tx.staffAppeal.findFirst({
        where: { accountId: account.id },
        orderBy: { submittedAt: 'desc' },
      });
      if (last && last.submittedAt.getTime() > Date.now() - APPEAL_EVERY_MS)
        throw new HttpException(
          {
            code: 'appeal_rate_limited',
            message: 'You can appeal once every 24 hours.',
            appealAvailableAt: new Date(
              last.submittedAt.getTime() + APPEAL_EVERY_MS,
            ),
          },
          429,
        );
      const now = new Date();
      let code = '';
      for (let i = 0; i < 4; i++) code += CODE[randomInt(CODE.length)];
      const appeal = await tx.staffAppeal.create({
        data: {
          code: `APL-${code}${String(randomInt(100)).padStart(2, '0')}`,
          restrictionId: r.id,
          accountId: account.id,
          text,
          submittedAt: now,
          dueAt: dueAt(now),
        },
      });
      await this.audit.append(
        {
          staffId: null,
          action: 'appeal.submitted',
          targetType: 'APPEAL',
          targetId: appeal.id,
          data: { restrictionId: r.id },
        },
        tx,
      );
      return { code: appeal.code, dueAt: appeal.dueAt };
    });
  }

  private async verifyTurnstile(token: string, ip?: string) {
    const secret = this.config.get('TURNSTILE_SECRET_KEY', { infer: true });
    if (!secret)
      throw new ForbiddenException({
        code: 'turnstile_unavailable',
        message: 'Appeals are briefly unavailable. Try again later.',
      });
    let ok = false;
    try {
      const res = await fetch(TURNSTILE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret,
          response: token,
          ...(ip ? { remoteip: ip } : {}),
        }),
        signal: AbortSignal.timeout(5000),
      });
      ok =
        res.ok &&
        ((await res.json()) as { success?: boolean }).success === true;
    } catch (error) {
      this.logger.warn(`Turnstile check failed: ${String(error)}`);
    }
    if (!ok)
      throw new BadRequestException({
        code: 'turnstile_failed',
        message: 'Confirm you are a person and try again.',
      });
  }

  /** The reviewer queue: appeals on restrictions the caller created are hidden (spec §9.4). */
  async queue(staffId: string, status: 'OPEN' | 'UPHELD' | 'OVERTURNED') {
    const rows = await this.control.staffAppeal.findMany({
      where: { status },
      orderBy: { dueAt: 'asc' },
      include: { restriction: true },
      take: 200,
    });
    const mine = rows.filter((a) => a.restriction.createdBy === staffId);
    const accounts = await this.control.account.findMany({
      where: { id: { in: rows.map((a) => a.accountId) } },
      select: { id: true, displayName: true },
    });
    return {
      hiddenCount: mine.length,
      items: rows
        .filter((a) => a.restriction.createdBy !== staffId)
        .map((a) => ({
          id: a.id,
          code: a.code,
          status: a.status,
          text: a.text,
          submittedAt: a.submittedAt,
          dueAt: a.dueAt,
          account: accounts.find((x) => x.id === a.accountId) ?? null,
          restriction: {
            id: a.restriction.id,
            code: a.restriction.code,
            kind: a.restriction.kind,
            category: a.restriction.category,
            until: a.restriction.until,
            internalNote: a.restriction.internalNote,
            createdBy: a.restriction.createdBy,
            startsAt: a.restriction.startsAt,
          },
        })),
    };
  }

  async load(id: string) {
    const a = await this.control.staffAppeal.findUnique({
      where: { id },
      include: { restriction: true },
    });
    if (!a)
      throw new NotFoundException({
        code: 'not_found',
        message: 'No such appeal.',
      });
    if (a.status !== 'OPEN')
      throw new ConflictException({
        code: 'already_decided',
        message: 'This appeal was decided already.',
      });
    return a;
  }

  async close(
    id: string,
    staffId: string,
    status: 'UPHELD' | 'OVERTURNED',
    note: string,
  ) {
    const done = await this.control.staffAppeal.updateMany({
      where: { id, status: 'OPEN' },
      data: {
        status,
        decidedBy: staffId,
        decidedAt: new Date(),
        internalNote: note.slice(0, 2000),
      },
    });
    if (done.count !== 1)
      throw new ConflictException({
        code: 'already_decided',
        message: 'This appeal was decided already.',
      });
    await this.audit.append({
      staffId,
      action: `appeal.${status.toLowerCase()}`,
      targetType: 'APPEAL',
      targetId: id,
    });
  }
}
