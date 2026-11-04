import 'dotenv/config';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { StaffAuditService } from '../src/staff/audit/staff-audit.service';

/** The staff audit chain against the real control database (DESK spec §11.5). */
describe('staff audit chain (e2e)', () => {
  const control = new ControlPrismaService({
    get: () => process.env.CONTROL_DATABASE_URL,
  } as never);
  const audit = new StaffAuditService(control);

  afterAll(() => control.$disconnect());

  it('links each row to the previous one and verifies', async () => {
    const a = await audit.append({ staffId: 's1', action: 'test.one' });
    const b = await audit.append({
      staffId: 's1',
      action: 'test.two',
      data: { x: 1 },
    });
    expect(b.seq).toBe(a.seq + 1n);
    const row = await control.staffAuditEvent.findUniqueOrThrow({
      where: { seq: b.seq },
    });
    expect(row.previousHash).toBe(a.hash);
    expect(await audit.verify()).toMatchObject({ valid: true });
  });

  it('20 concurrent appends get consecutive sequence numbers', async () => {
    const results = await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        audit.append({ staffId: 's2', action: `test.c${i}` }),
      ),
    );
    const seqs = results.map((r) => r.seq).sort((x, y) => (x < y ? -1 : 1));
    for (let i = 1; i < seqs.length; i++)
      expect(seqs[i]).toBe(seqs[i - 1]! + 1n);
    expect(await audit.verify()).toMatchObject({ valid: true });
  });

  it('an edited row breaks verification at that row', async () => {
    const { seq } = await audit.append({
      staffId: 's3',
      action: 'test.tamper',
      data: { v: 1 },
    });
    await control.$executeRaw`UPDATE staff_audit_events SET data = '{"v":2}' WHERE seq = ${seq}`;
    try {
      expect(await audit.verify()).toEqual({
        valid: false,
        brokenAtSeq: seq.toString(),
      });
    } finally {
      await control.$executeRaw`UPDATE staff_audit_events SET data = '{"v":1}' WHERE seq = ${seq}`;
    }
    expect(await audit.verify()).toMatchObject({ valid: true });
  });
});
