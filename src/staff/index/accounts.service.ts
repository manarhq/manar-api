import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { VerifiedIdentity } from '../../auth/token-verifier.service';
import type { AppConfig } from '../../config/env.validation';
import { ControlPrismaService } from '../../database/control-prisma.service';
import { fingerprint, normalizeEmail } from '../restrictions/fingerprints';

const TOUCH_EVERY_MS = 10 * 60 * 1000;
const MEMO_MAX = 50_000;

/**
 * One `accounts` row per person who signs in to the hosted product (DESK spec §17.1). Upserted on
 * a verified token at most once per 10 minutes per account (AC-42): an in-process memo first, then
 * a conditional upsert, so replicas and a busy session never write more than that. Never throws
 * into the request: the index is for staff, not for access.
 */
@Injectable()
export class AccountsService {
  private readonly logger = new Logger(AccountsService.name);
  private readonly touched = new Map<string, number>();

  constructor(
    private readonly control: ControlPrismaService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  /** Resolves when the write is done (or skipped); never rejects. */
  touch(id: VerifiedIdentity): Promise<void> {
    if (id.boundTenant) return Promise.resolve(); // legacy realm users are listed from memberships
    const key = `${id.issuer}|${id.subject}`;
    const now = Date.now();
    if ((this.touched.get(key) ?? 0) > now - TOUCH_EVERY_MS)
      return Promise.resolve();
    this.touched.set(key, now);
    if (this.touched.size > MEMO_MAX) {
      const oldest = this.touched.keys().next().value;
      if (oldest !== undefined) this.touched.delete(oldest);
    }
    return this.upsert(id).catch((e: unknown) =>
      this.logger.warn(`account index not updated: ${String(e)}`),
    );
  }

  private async upsert(id: VerifiedIdentity): Promise<void> {
    const email = id.email ? normalizeEmail(id.email) : null;
    const idp =
      id.idp === 'microsoft' || id.idp === 'github'
        ? id.idp
        : id.idp
          ? id.idp
          : 'email';
    const fpKey = this.config.get('RESTRICTION_FINGERPRINT_KEY', {
      infer: true,
    });
    const idpUserHash =
      fpKey && id.idp === 'microsoft' && id.tid && id.oid
        ? fingerprint('IDP_IDENTITY', `microsoft:${id.tid}:${id.oid}`, fpKey)
        : null;
    await this.control.$executeRaw`
      INSERT INTO accounts (id, issuer, subject, "displayName", "normalizedEmail", "emailVerified", idp, "idpUserHash", "createdAt", "lastSeenAt")
      VALUES (gen_random_uuid()::text, ${id.issuer}, ${id.subject}, ${id.displayName ?? ''}, ${email}, ${!id.idp}, ${idp}, ${idpUserHash}, now(), now())
      ON CONFLICT (issuer, subject) DO UPDATE SET
        "lastSeenAt" = now(),
        "displayName" = COALESCE(NULLIF(EXCLUDED."displayName", ''), accounts."displayName"),
        "normalizedEmail" = COALESCE(EXCLUDED."normalizedEmail", accounts."normalizedEmail"),
        "idpUserHash" = COALESCE(EXCLUDED."idpUserHash", accounts."idpUserHash")
      WHERE accounts."lastSeenAt" < now() - interval '10 minutes'`;
  }

  async idFor(issuer: string, subject: string): Promise<string | null> {
    const row = await this.control.account.findUnique({
      where: { issuer_subject: { issuer, subject } },
      select: { id: true },
    });
    return row?.id ?? null;
  }
}
