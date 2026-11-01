/* eslint-disable @typescript-eslint/require-await -- in-memory fakes of async Prisma calls */
import { describe, expect, it, vi } from 'vitest';
import { renderTrialReminder } from './trial-reminder';
import { TrialReminderService } from './trial-reminder.service';

const NOW = new Date('2026-11-01T00:00:00Z');
function make(
  over: {
    claimEnds?: Date;
    sent?: boolean;
    mailOk?: boolean;
    sub?: string;
  } = {},
) {
  const claim = {
    id: 'c1',
    issuer: 'i',
    subject: 's',
    tenantId: 't',
    stripeSubscriptionId: 'sub_1',
    trialEndsAt: over.claimEnds ?? new Date('2026-11-06T00:00:00Z'),
    reminderSentAt: over.sent ? NOW : (null as Date | null),
    keptAt: null,
  };
  const send = vi.fn(async () => over.mailOk ?? true);
  const control = {
    launchOfferClaim: {
      findMany: async ({
        where,
      }: {
        where: { trialEndsAt: { gt: Date; lte: Date } };
      }) =>
        !claim.reminderSentAt &&
        claim.trialEndsAt > where.trialEndsAt.gt &&
        claim.trialEndsAt <= where.trialEndsAt.lte
          ? [claim]
          : [],
      updateMany: async () => {
        if (claim.reminderSentAt) return { count: 0 };
        claim.reminderSentAt = NOW;
        return { count: 1 };
      },
      update: async ({ data }: { data: { reminderSentAt: Date | null } }) =>
        void (claim.reminderSentAt = data.reminderSentAt),
    },
    membership: {
      findUnique: async () => ({
        email: 'a@b.c',
        status: 'ACTIVE',
        locale: 'ar',
      }),
    },
    tenantEntitlement: {
      findUnique: async () => ({ stripeSubscriptionId: over.sub ?? 'sub_1' }),
    },
  };
  const svc = new TrialReminderService(
    control as never,
    { configured: true, send } as never,
    { verified: async () => 'a@b.c' } as never,
    { get: () => 'https://console.test' } as never,
  );
  return { svc, send, claim };
}

describe('trial reminder', () => {
  it('sends once, 7 days ahead, in the person language, with the billing link', async () => {
    const { svc, send } = make();
    expect(await svc.sendDue(NOW)).toEqual({ sent: 1, failed: 0 });
    const mail = (
      send.mock.calls[0] as unknown as [{ html: string; text: string }]
    )[0];
    expect(mail.html).toContain('dir="rtl"');
    expect(mail.text).toContain('https://console.test/settings/billing');
    expect(await svc.sendDue(NOW)).toEqual({ sent: 0, failed: 0 });
  });
  it('waits until 7 days before, and skips a replaced subscription', async () => {
    expect(
      (
        await make({ claimEnds: new Date('2026-12-01T00:00:00Z') }).svc.sendDue(
          NOW,
        )
      ).sent,
    ).toBe(0);
    expect((await make({ sub: 'sub_other' }).svc.sendDue(NOW)).sent).toBe(0);
  });
  it('gives the claim back when the mail is refused, so the next tick retries', async () => {
    const { svc, claim } = make({ mailOk: false });
    expect(await svc.sendDue(NOW)).toEqual({ sent: 0, failed: 1 });
    expect(claim.reminderSentAt).toBeNull();
  });
  it('renders English too', () => {
    const m = renderTrialReminder({
      locale: 'en',
      endsAt: NOW,
      link: 'https://x/y',
    });
    expect(m.text).toContain('UAE VAT');
  });
});
