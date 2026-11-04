import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { ControlPrismaService } from '../src/database/control-prisma.service';

/** The DESK Phase 1 control tables and the constraints the services rely on. */
describe('DESK control schema (e2e)', () => {
  const control = new ControlPrismaService({
    get: () => process.env.CONTROL_DATABASE_URL,
  } as never);
  const target = randomUUID();
  const request = (status: 'PENDING' | 'EXECUTED') =>
    control.staffChangeRequest.create({
      data: {
        code: `CR-T-${randomUUID().slice(0, 8)}`,
        kind: 'unban',
        targetId: target,
        payload: {},
        reason: 'schema test',
        proposedBy: 'test',
        status,
        expiresAt: new Date(Date.now() + 60_000),
      },
    });

  afterAll(async () => {
    await control.staffChangeRequest.deleteMany({
      where: { targetId: target },
    });
    await control.$disconnect();
  });

  it('allows one open change request per kind and target', async () => {
    await request('EXECUTED');
    await request('PENDING');
    await expect(request('PENDING')).rejects.toMatchObject({ code: 'P2002' });
  });

  it('has trigram indexes for search', async () => {
    const rows = await control.$queryRaw<{ indexname: string }[]>`
      SELECT indexname FROM pg_indexes
      WHERE indexname IN ('accounts_displayName_trgm', 'tenants_name_trgm', 'staff_device_index_hostname_trgm')`;
    expect(rows.map((r) => r.indexname).sort()).toEqual([
      'accounts_displayName_trgm',
      'staff_device_index_hostname_trgm',
      'tenants_name_trgm',
    ]);
  });
});
