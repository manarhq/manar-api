import { Injectable } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';

/** The shared realm stores `<id>@idp.invalid` for Microsoft and GitHub users: never a real address. */
export const isPlaceholderEmail = (e: string | undefined | null): boolean =>
  !e || /\.invalid$/i.test(e.trim());

export interface SignedInAs {
  issuer: string;
  subject: string;
  email?: string;
  /** How the person signed in (`microsoft`, `github`); absent for an email link. */
  idp?: string;
}

/**
 * A person's verified contact email, kept in the control database. Everything that sends mail or
 * creates a Stripe customer reads it from here (never from the token, whose email may be the
 * `.invalid` placeholder). Email-link sign-ins are verified by the link itself, so their sign-in
 * address is recorded as verified on sign-in (`noteSignIn`).
 */
@Injectable()
export class ContactEmailService {
  constructor(private readonly control: ControlPrismaService) {}

  /** The verified address, or null. */
  async verified(issuer: string, subject: string): Promise<string | null> {
    const r = await this.control.contactEmail.findUnique({
      where: { issuer_subject: { issuer, subject } },
    });
    return r?.verifiedAt && r.email && !isPlaceholderEmail(r.email)
      ? r.email
      : null;
  }

  /** Verified addresses for many people at once, keyed `issuer\nsubject`. */
  async verifiedMany(
    people: { issuer: string; subject: string }[],
  ): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    if (!people.length) return out;
    const rows = await this.control.contactEmail.findMany({
      where: {
        verifiedAt: { not: null },
        OR: people.map((p) => ({ issuer: p.issuer, subject: p.subject })),
      },
    });
    for (const r of rows)
      if (r.email && !isPlaceholderEmail(r.email))
        out.set(`${r.issuer}\n${r.subject}`, r.email);
    return out;
  }

  /** Records how the person signed in, and pre-verifies an email-link sign-in address. */
  async noteSignIn(id: SignedInAs): Promise<void> {
    const key = { issuer_subject: { issuer: id.issuer, subject: id.subject } };
    const emailLink = !id.idp && !isPlaceholderEmail(id.email);
    await this.control.contactEmail.upsert({
      where: key,
      create: {
        issuer: id.issuer,
        subject: id.subject,
        idp: id.idp ?? null,
        ...(emailLink
          ? { email: id.email!.trim().toLowerCase(), verifiedAt: new Date() }
          : {}),
      },
      update: { idp: id.idp ?? null },
    });
    // An email-link person with no verified address yet (or a changed one) gets the link address.
    if (emailLink) {
      await this.control.contactEmail.updateMany({
        where: { issuer: id.issuer, subject: id.subject, verifiedAt: null },
        data: { email: id.email!.trim().toLowerCase(), verifiedAt: new Date() },
      });
    }
  }

  async idpOf(issuer: string, subject: string): Promise<string | null> {
    return (
      (
        await this.control.contactEmail.findUnique({
          where: { issuer_subject: { issuer, subject } },
        })
      )?.idp ?? null
    );
  }
}
