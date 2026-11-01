import { createHmac, randomInt, timingSafeEqual } from 'node:crypto';
import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ContactEmailService,
  isPlaceholderEmail,
  type SignedInAs,
} from '../contact/contact-email.service';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import { MailerService } from './mailer.service';

const CODE_TTL_MS = 10 * 60_000;
const MAX_ATTEMPTS = 5;
const MAX_SENDS_PER_HOUR = 5;
const HOUR_MS = 3_600_000;

const COPY = {
  en: {
    subject: 'Your Manar confirmation code',
    body: (c: string) =>
      `Your Manar confirmation code is ${c}. It works for 10 minutes. If you did not ask for it, ignore this email.`,
  },
  ar: {
    subject: 'رمز التأكيد الخاص بك في منار',
    body: (c: string) =>
      `رمز التأكيد الخاص بك في منار هو ${c}. يعمل لمدة 10 دقائق. إذا لم تطلبه فتجاهل هذه الرسالة.`,
  },
} as const;

/**
 * Verifying a contact email with a 6-digit code (spec: the shared realm stores a placeholder
 * email for Microsoft and GitHub users). The code is HMAC-stored (keyed by the link secret and
 * bound to the person and the address), lives 10 minutes, allows 5 attempts, and at most 5 codes
 * are sent per person per hour.
 */
@Injectable()
export class ContactFlowService {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly contact: ContactEmailService,
    private readonly mailer: MailerService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  private mac(
    who: { issuer: string; subject: string },
    email: string,
    code: string,
  ) {
    const secret = this.config.get('MANAR_LINK_SECRET', { infer: true });
    if (!secret) throw new ServiceUnavailableException('links_not_configured');
    return createHmac('sha256', secret)
      .update(`${who.issuer}\n${who.subject}\n${email}\n${code}`)
      .digest('hex');
  }

  async status(id: SignedInAs) {
    await this.contact.noteSignIn(id);
    const email = await this.contact.verified(id.issuer, id.subject);
    const row = await this.control.contactEmail.findUnique({
      where: { issuer_subject: { issuer: id.issuer, subject: id.subject } },
    });
    return {
      email,
      verified: !!email,
      // The first-run step: the sign-in address is the placeholder and nothing is verified yet.
      needsEmail: !email && isPlaceholderEmail(id.email),
      pending:
        !!row?.pendingEmail &&
        !!row.codeExpiresAt &&
        row.codeExpiresAt > new Date(),
    };
  }

  async request(id: SignedInAs, rawEmail: string, locale: 'en' | 'ar') {
    const email = rawEmail.trim().toLowerCase();
    if (isPlaceholderEmail(email))
      throw new BadRequestException('contact_email_invalid');
    const key = { issuer_subject: { issuer: id.issuer, subject: id.subject } };
    await this.contact.noteSignIn(id);
    const row = await this.control.contactEmail.findUniqueOrThrow({
      where: key,
    });
    const now = new Date();
    const fresh =
      row.windowStartedAt &&
      now.getTime() - row.windowStartedAt.getTime() < HOUR_MS;
    if (fresh && row.sendsInWindow >= MAX_SENDS_PER_HOUR)
      throw new HttpException('too_many_codes', 429);
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    await this.control.contactEmail.update({
      where: key,
      data: {
        pendingEmail: email,
        codeHash: this.mac(id, email, code),
        codeExpiresAt: new Date(now.getTime() + CODE_TTL_MS),
        attempts: 0,
        sendsInWindow: fresh ? row.sendsInWindow + 1 : 1,
        windowStartedAt: fresh ? row.windowStartedAt : now,
      },
    });
    const c = COPY[locale];
    const sent = await this.mailer.send({
      to: email,
      subject: c.subject,
      text: `${c.body(code)}\n`,
      html: `<p dir="${locale === 'ar' ? 'rtl' : 'ltr'}">${c.body(`<b>${code}</b>`)}</p>`,
    });
    if (!sent) throw new ServiceUnavailableException('mail_unavailable');
    return { sent: true };
  }

  async confirm(id: SignedInAs, code: string) {
    const key = { issuer_subject: { issuer: id.issuer, subject: id.subject } };
    const row = await this.control.contactEmail.findUnique({ where: key });
    if (
      !row?.pendingEmail ||
      !row.codeHash ||
      !row.codeExpiresAt ||
      row.codeExpiresAt <= new Date()
    )
      throw new ForbiddenException('code_expired');
    // Take an attempt first, atomically, so parallel guesses still total 5.
    const took = await this.control.contactEmail.updateMany({
      where: {
        ...id2(id),
        attempts: { lt: MAX_ATTEMPTS },
        codeHash: row.codeHash,
      },
      data: { attempts: { increment: 1 } },
    });
    if (took.count !== 1) {
      await this.control.contactEmail.update({
        where: key,
        data: { pendingEmail: null, codeHash: null, codeExpiresAt: null },
      });
      throw new ForbiddenException('code_expired');
    }
    const want = Buffer.from(row.codeHash);
    const got = Buffer.from(this.mac(id, row.pendingEmail, code.trim()));
    if (want.length !== got.length || !timingSafeEqual(want, got))
      throw new ForbiddenException('code_wrong');
    await this.control.contactEmail.update({
      where: key,
      data: {
        email: row.pendingEmail,
        verifiedAt: new Date(),
        pendingEmail: null,
        codeHash: null,
        codeExpiresAt: null,
        attempts: 0,
      },
    });
    return { email: row.pendingEmail, verified: true };
  }
}

const id2 = (id: { issuer: string; subject: string }) => ({
  issuer: id.issuer,
  subject: id.subject,
});
