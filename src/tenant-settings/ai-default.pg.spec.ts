import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import { AiDefaultService } from './ai-default.service';

/** Real Postgres: CONTROL_DATABASE_URL (migrations applied). The final flip is one guarded UPDATE. */
const url = process.env.CONTROL_DATABASE_URL;
describe.skipIf(!url)('ai:default-on guarded flip (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const service = new AiDefaultService(
    control,
    null as never,
    null as never,
    null as never,
  );
  const ids: string[] = [];
  afterAll(async () => {
    await control.enterpriseProfile.deleteMany({
      where: { tenantId: { in: ids } },
    });
    await control.tenant.deleteMany({ where: { id: { in: ids } } });
    await control.$disconnect();
  });

  const mk = async (data: object = {}) => {
    const t = await control.tenant.create({
      data: {
        slug: `gf-${randomUUID().slice(0, 8)}`,
        name: 'g',
        status: 'ACTIVE',
        sector: 'COMMERCIAL',
        allowExternalAi: false,
        ...data,
      },
    });
    ids.push(t.id);
    return t;
  };

  it('flips an eligible workspace once, and refuses after any change between the read and the write', async () => {
    await control.$connect();
    const ok = await mk();
    expect(await service.guardedFlip(ok.id)).toBe(1);
    const row = await control.tenant.findUniqueOrThrow({
      where: { id: ok.id },
    });
    expect(row).toMatchObject({
      allowExternalAi: true,
      aiDefaultNoticePending: true,
    });
    // Already on: a second run changes nothing.
    expect(await service.guardedFlip(ok.id)).toBe(0);

    // Each of these happens "mid-run", after the workspace was judged eligible.
    const gov = await mk({ sector: 'GOVERNMENT' });
    const unknown = await mk({ sector: null });
    const air = await mk({ residency: 'AIR_GAPPED' });
    const suspended = await mk({ status: 'SUSPENDED' });
    const chosen = await mk({ allowExternalAiChosen: true });
    const profiled = await mk();
    await control.enterpriseProfile.create({
      data: {
        tenantId: profiled.id,
        sector: 'GOVERNMENT',
        publicSlug: `gf-${randomUUID()}`,
      },
    });
    for (const t of [gov, unknown, air, suspended, chosen, profiled]) {
      expect(await service.guardedFlip(t.id)).toBe(0);
      const r = await control.tenant.findUniqueOrThrow({ where: { id: t.id } });
      expect(r.allowExternalAi).toBe(false);
    }
  });
});
