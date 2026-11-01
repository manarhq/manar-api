/* eslint-disable @typescript-eslint/require-await -- in-memory fakes of async Prisma calls */
import { describe, expect, it, vi } from 'vitest';
import { ContactEmailService } from '../contact/contact-email.service';
import { ContactFlowService } from './contact-flow.service';
import { MailerService } from './mailer.service';

type Row = Record<string, unknown> & { attempts: number };

function make() {
  let row: Row | null = null;
  const merge = (d: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(d)) {
      const inc = (v as { increment?: number } | null)?.increment;
      row![k] = inc !== undefined ? (row![k] as number) + inc : v;
    }
  };
  const control = {
    contactEmail: {
      findUnique: async () => row,
      findUniqueOrThrow: async () => row!,
      upsert: async ({ create }: { create: Record<string, unknown> }) => {
        row ??= { attempts: 0, sendsInWindow: 0, ...create } as Row;
        return row;
      },
      updateMany: async ({
        where,
        data,
      }: {
        where: { attempts?: { lt: number }; verifiedAt?: null };
        data: Record<string, unknown>;
      }) => {
        if (!row) return { count: 0 };
        if (where.attempts && !(row.attempts < where.attempts.lt))
          return { count: 0 };
        if ('verifiedAt' in where && row.verifiedAt) return { count: 0 };
        merge(data);
        return { count: 1 };
      },
      update: async ({ data }: { data: Record<string, unknown> }) => {
        merge(data);
        return row;
      },
    },
  };
  const sent: { to: string; text: string }[] = [];
  const mailer = {
    send: vi.fn(
      async (m: { to: string; text: string }) => (sent.push(m), true),
    ),
  };
  const contact = new ContactEmailService(control as never);
  const svc = new ContactFlowService(
    control as never,
    contact,
    mailer as unknown as MailerService,
    { get: () => 's'.repeat(32) } as never,
  );
  const who = {
    issuer: 'i',
    subject: 'u',
    idp: 'microsoft',
    email: 'u@idp.invalid',
  };
  const codeOf = () => /(\d{6})/.exec(sent.at(-1)!.text)![1]!;
  return { svc, contact, who, sent, codeOf, mailer, row: () => row };
}

describe('contact email', () => {
  it('asks a Microsoft user with the placeholder email for one, then verifies it with the code', async () => {
    const { svc, who, codeOf, contact } = make();
    expect((await svc.status(who)).needsEmail).toBe(true);
    await svc.request(who, 'Me@Acme.io', 'en');
    await expect(svc.confirm(who, '000000')).rejects.toThrow('code_wrong');
    await svc.confirm(who, codeOf());
    expect(await contact.verified('i', 'u')).toBe('me@acme.io');
    expect((await svc.status(who)).needsEmail).toBe(false);
  });

  it('refuses a placeholder address and never mails it', async () => {
    const { svc, who, mailer } = make();
    await expect(svc.request(who, 'x@idp.invalid', 'en')).rejects.toThrow(
      'contact_email_invalid',
    );
    expect(mailer.send).not.toHaveBeenCalled();
  });

  it('allows 5 attempts, then the code is gone even if the 6th is right', async () => {
    const { svc, who, codeOf } = make();
    await svc.request(who, 'me@acme.io', 'ar');
    const good = codeOf();
    const wrong = good === '111111' ? '222222' : '111111';
    for (let i = 0; i < 5; i++)
      await expect(svc.confirm(who, wrong)).rejects.toThrow('code_wrong');
    await expect(svc.confirm(who, good)).rejects.toThrow('code_expired');
  });

  it('limits how many codes are sent per hour', async () => {
    const { svc, who } = make();
    for (let i = 0; i < 5; i++) await svc.request(who, 'me@acme.io', 'en');
    await expect(svc.request(who, 'me@acme.io', 'en')).rejects.toThrow(
      'too_many_codes',
    );
  });

  it('pre-verifies an email-link sign-in address', async () => {
    const { svc, contact } = make();
    await svc.status({ issuer: 'i', subject: 'u', email: 'A@Corp.io' });
    expect(await contact.verified('i', 'u')).toBe('a@corp.io');
  });
});
