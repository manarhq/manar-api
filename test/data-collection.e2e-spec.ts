import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DataCollectionService } from '../src/data-collection/data-collection.service';
import { PostHogClient } from '../src/data-collection/posthog.client';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { fakeConfigService } from './support/audit-test-config';

/** Product improvement data against the real control database (migration, defaults, delete, purge). */
describe('data collection (e2e)', () => {
  let control: ControlPrismaService;
  let svc: DataCollectionService;
  const issuer = `https://kc.test/realms/${randomUUID().slice(0, 8)}`;
  const subject = 'user-1';
  let tenantId = '';
  const audit = {
    events: [] as unknown[],
    record: (...a: unknown[]) => Promise.resolve(void audit.events.push(a)),
  };

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    svc = new DataCollectionService(
      control,
      new PostHogClient({ get: () => undefined } as never),
      audit as never,
    );
    tenantId = (
      await control.tenant.create({
        data: {
          slug: `dc-${randomUUID().slice(0, 8)}`,
          name: 'Acme',
          status: 'ACTIVE',
          kind: 'COMPANY',
        },
      })
    ).id;
  });

  afterAll(async () => {
    await control.productSample.deleteMany({ where: { issuer } });
    await control.userDataPreference.deleteMany({ where: { issuer } });
    await control.tenant.deleteMany({ where: { id: tenantId } });
    await control.$disconnect();
  });

  const sample = (createdAt: Date) => ({
    issuer,
    subject,
    tenantId,
    kind: 'command',
    tool: 'claude',
    decision: 'ask',
    text: 'ls',
    at: createdAt,
    aiTrainingAllowed: true,
    createdAt,
  });

  it('everything is on by default, org flags show for a company workspace', async () => {
    expect(await svc.getMine(issuer, subject, tenantId)).toEqual({
      improveManar: true,
      aiTraining: true,
      org: { improveManar: true, aiTraining: true },
      effective: { improveManar: true, aiTraining: true },
      noticeDismissed: false,
    });
  });

  it('org off overrides the member; the manager change is audited', async () => {
    await svc.setOrg(tenantId, 'mgr', { aiTraining: false });
    expect((await svc.getMine(issuer, subject, tenantId)).effective).toEqual({
      improveManar: true,
      aiTraining: false,
    });
    expect(audit.events).toHaveLength(1);
    await svc.setOrg(tenantId, 'mgr', { aiTraining: true });
  });

  it('opt-out deletes the samples at once; the purge removes only >12 months', async () => {
    const old = new Date(Date.now() - 400 * 86_400_000);
    await control.productSample.createMany({
      data: [sample(old), sample(new Date())],
    });
    expect(await svc.purgeOld()).toEqual({ deleted: 1 });
    expect(await control.productSample.count({ where: { issuer } })).toBe(1);
    await svc.setMine(issuer, subject, tenantId, { improveManar: false });
    expect(await control.productSample.count({ where: { issuer } })).toBe(0);
    const mine = await svc.getMine(issuer, subject, tenantId);
    expect(mine.effective).toEqual({ improveManar: false, aiTraining: false });
  });
});
