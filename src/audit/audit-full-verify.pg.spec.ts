import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import { AuditFullVerifyService } from './audit-full-verify.service';

/** Real Postgres: the claim, the never-older-over-newer write and the error result. */
const url = process.env.CONTROL_DATABASE_URL;
describe.skipIf(!url)('AuditFullVerifyService (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const ids: string[] = [];
  const fresh = () => {
    const id = `fv-${randomUUID()}`;
    ids.push(id);
    return id;
  };
  const make = (verify: () => Promise<unknown>) =>
    new AuditFullVerifyService(
      control,
      { getClient: () => Promise.resolve({}) } as never,
      { verifyAuditChain: vi.fn(verify) } as never,
    );
  const day = 24 * 3_600_000;

  beforeAll(() => control.$connect());
  afterAll(async () => {
    await control.auditFullVerification.deleteMany({
      where: { tenantId: { in: ids } },
    });
    await control.$disconnect();
  });

  it('two workers claiming one tenant: exactly one wins; the claim frees after the run', async () => {
    const id = fresh();
    const svc = make(() => Promise.resolve({ valid: true }));
    const now = new Date();
    const due = new Date(now.getTime() + 1000);
    const [a, b] = await Promise.all([
      svc.claim(id, now, due),
      svc.claim(id, now, due),
    ]);
    expect([a, b].sort()).toEqual([false, true]);
    await svc.verifyTenant(id);
    // Run recorded before the boundary: due again, claimable now that the claim is released.
    await control.auditFullVerification.update({
      where: { tenantId: id },
      data: { claimedAt: null },
    });
    expect(await svc.claim(id, new Date(), new Date(Date.now() + day))).toBe(
      true,
    );
    // Not due again until the next boundary:
    await control.auditFullVerification.update({
      where: { tenantId: id },
      data: { claimedAt: null },
    });
    expect(await svc.claim(id, new Date(), new Date(Date.now() - day))).toBe(
      false,
    );
  });

  it('passed, then a run that throws: the stored result is error and never "passed"', async () => {
    const id = fresh();
    await make(() => Promise.resolve({ valid: true })).verifyTenant(id);
    expect(
      (await make(() => Promise.resolve({ valid: true })).status(id)).state,
    ).toBe('passed');

    const boom = make(() =>
      Promise.reject(new RangeError('Invalid time value')),
    );
    await expect(boom.verifyTenant(id)).rejects.toThrow('Invalid time value');
    const s = await boom.status(id);
    expect(s.state).toBe('error');
    expect(s.lastFullVerifiedAt).toBeInstanceOf(Date); // when it last passed, for display only
  });

  it('a run that started earlier never overwrites the result of one that started later', async () => {
    const id = fresh();
    let release!: () => void;
    const slowOld = make(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ valid: true });
        }),
    );
    const oldRun = slowOld.verifyTenant(id); // starts first, still running
    await new Promise((r) => setTimeout(r, 20));
    await make(() =>
      Promise.resolve({ valid: false, brokenAt: 'e5' }),
    ).verifyTenant(id); // starts later
    release();
    await oldRun;
    const s = await slowOld.status(id);
    expect(s.state).toBe('failed');
    expect(s.brokenAt).toBe('e5');
  });
});
