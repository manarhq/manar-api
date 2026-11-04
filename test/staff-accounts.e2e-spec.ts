import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { AccountsService } from '../src/staff/index/accounts.service';

/** The account index written from verified tokens (DESK spec §17.1, AC-42). */
describe('account index (e2e)', () => {
  const env: Record<string, unknown> = {
    ...process.env,
    RESTRICTION_FINGERPRINT_KEY: 'e2e-fingerprint-key-not-a-secret-000000',
  };
  const control = new ControlPrismaService({
    get: (k: string) => env[k],
  } as never);
  const issuer = `https://e2e.test/realms/accounts-${randomUUID().slice(0, 8)}`;
  afterAll(async () => {
    await control.account.deleteMany({ where: { issuer } });
    await control.$disconnect();
  });

  it('creates one row per person, normalises the email and writes at most every 10 minutes', async () => {
    const accounts = new AccountsService(control, {
      get: (k: string) => env[k],
    } as never);
    const id = {
      issuer,
      subject: 's1',
      email: 'J.Doe+news@GoogleMail.com',
      displayName: 'Jane Doe',
      wids: [],
    };
    await accounts.touch(id);
    const first = await control.account.findUniqueOrThrow({
      where: { issuer_subject: { issuer, subject: 's1' } },
    });
    expect(first).toMatchObject({
      normalizedEmail: 'jdoe@gmail.com',
      displayName: 'Jane Doe',
      emailVerified: true,
      idp: 'email',
    });
    // A second replica (fresh memo) inside 10 minutes does not write.
    await new AccountsService(control, {
      get: (k: string) => env[k],
    } as never).touch({ ...id, displayName: 'Changed' });
    const again = await control.account.findUniqueOrThrow({
      where: { id: first.id },
    });
    expect(again.lastSeenAt).toEqual(first.lastSeenAt);
    expect(again.displayName).toBe('Jane Doe');
    // Older than 10 minutes: refreshed.
    await control.account.update({
      where: { id: first.id },
      data: { lastSeenAt: new Date(Date.now() - 11 * 60_000) },
    });
    await new AccountsService(control, {
      get: (k: string) => env[k],
    } as never).touch({ ...id, displayName: 'Changed' });
    expect(
      (await control.account.findUniqueOrThrow({ where: { id: first.id } }))
        .displayName,
    ).toBe('Changed');
  });

  it('keeps a keyed hash of the Microsoft identity, never the raw ids', async () => {
    const accounts = new AccountsService(control, {
      get: (k: string) => env[k],
    } as never);
    await accounts.touch({
      issuer,
      subject: 's2',
      idp: 'microsoft',
      tid: 'tid-1',
      oid: 'oid-1',
      wids: [],
    });
    const row = await control.account.findUniqueOrThrow({
      where: { issuer_subject: { issuer, subject: 's2' } },
    });
    expect(row.idp).toBe('microsoft');
    expect(row.emailVerified).toBe(false);
    expect(row.idpUserHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(row)).not.toContain('oid-1');
  });
});
