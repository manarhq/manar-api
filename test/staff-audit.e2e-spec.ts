import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import { StaffAuditService } from '../src/staff/audit/staff-audit.service';

/**
 * The staff audit chain against the real control database and OpenBao (DESK spec §11.5, security
 * review of 4 Nov): every stored column is hashed, and the head is anchored outside the table by
 * signed checkpoints whose newest one is named in OpenBao.
 */
describe('staff audit chain (e2e)', () => {
  const env = (k: string) => process.env[k];
  const control = new ControlPrismaService({
    get: () => env('CONTROL_DATABASE_URL'),
  } as never);
  const kv = new OpenBaoKvClient({ get: env } as never);
  const signer = new CheckpointSigner(kv);
  // Each run anchors its own chain id so a test never disturbs another database's anchor.
  const chainId = `staff-audit-e2e-${randomUUID().slice(0, 8)}`;
  const audit = new StaffAuditService(control, signer, kv, chainId);

  type Row = Awaited<
    ReturnType<typeof control.staffAuditEvent.findMany>
  >[number];
  type Cp = Awaited<
    ReturnType<typeof control.staffAuditCheckpoint.findMany>
  >[number];
  let rowsBackup: Row[] = [];
  let cpsBackup: Cp[] = [];
  const backup = async () => {
    rowsBackup = await control.staffAuditEvent.findMany({
      orderBy: { seq: 'asc' },
    });
    cpsBackup = await control.staffAuditCheckpoint.findMany({
      orderBy: { seq: 'asc' },
    });
  };
  const restore = async () => {
    await control.staffAuditCheckpoint.deleteMany({});
    await control.staffAuditEvent.deleteMany({});
    await control.staffAuditEvent.createMany({
      data: rowsBackup.map((r) => ({ ...r, data: r.data as object })),
    });
    await control.staffAuditCheckpoint.createMany({ data: cpsBackup });
  };

  beforeAll(async () => {
    // A clean chain for this file: any rows left by earlier files belong to an older anchor.
    await control.staffAuditCheckpoint.deleteMany({});
    await control.staffAuditEvent.deleteMany({});
  });
  afterAll(() => control.$disconnect());

  it('links each row to the previous one and verifies', async () => {
    const a = await audit.append({ staffId: 's1', action: 'test.one' });
    const b = await audit.append({
      staffId: 's1',
      action: 'test.two',
      data: { x: 1 },
      ip: '203.0.113.7',
      requestId: 'req-1',
    });
    expect(b.seq).toBe(a.seq + 1n);
    const row = await control.staffAuditEvent.findUniqueOrThrow({
      where: { seq: b.seq },
    });
    expect(row.previousHash).toBe(a.hash);
    await audit.checkpoint();
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
    await audit.checkpoint();
    expect(await audit.verify()).toMatchObject({ valid: true });
  });

  describe.each([
    ['data', `data = '{"v":2}'`],
    ['ip', `ip = '198.51.100.9'`],
    ['requestId', `"requestId" = 'req-forged'`],
    ['staffId', `"staffId" = 'someone-else'`],
    ['action', `action = 'test.other'`],
    ['targetType', `"targetType" = 'TENANT'`],
    ['targetId', `"targetId" = 'other-target'`],
    ['at', `at = at + interval '1 second'`],
    ['id', `id = gen_random_uuid()::text`],
  ])('editing the %s column', (_column, assignment) => {
    it('breaks verification at that row', async () => {
      const { seq } = await audit.append({
        staffId: 's3',
        action: 'test.tamper',
        targetType: 'ACCOUNT',
        targetId: 'a1',
        data: { v: 1 },
        ip: '203.0.113.8',
        requestId: 'req-2',
      });
      await backup();
      await control.$executeRawUnsafe(
        `UPDATE staff_audit_events SET ${assignment} WHERE seq = $1`,
        seq,
      );
      try {
        expect(await audit.verify()).toMatchObject({
          valid: false,
          brokenAtSeq: seq.toString(),
        });
      } finally {
        await restore();
      }
      expect(await audit.verify()).toMatchObject({ valid: true });
    });
  });

  it('detects truncation of the whole table while a checkpoint exists', async () => {
    await audit.append({ staffId: 's4', action: 'test.before-truncate' });
    await audit.checkpoint();
    await backup();
    await control.staffAuditEvent.deleteMany({});
    try {
      expect(await audit.verify()).toMatchObject({ valid: false });
      // Deleting the checkpoints too: OpenBao still names the newest one.
      await control.staffAuditCheckpoint.deleteMany({});
      expect(await audit.verify()).toMatchObject({ valid: false });
    } finally {
      await restore();
    }
    expect(await audit.verify()).toMatchObject({ valid: true });
  });

  it('detects deleting the last rows covered by a checkpoint', async () => {
    for (let i = 0; i < 3; i++)
      await audit.append({ staffId: 's5', action: `test.tail${i}` });
    await audit.checkpoint();
    await backup();
    const last = rowsBackup.at(-1)!.seq;
    await control.$executeRaw`DELETE FROM staff_audit_events WHERE seq > ${last - 3n}`;
    try {
      expect(await audit.verify()).toMatchObject({ valid: false });
    } finally {
      await restore();
    }
  });

  it('detects deleting the newest checkpoint together with the rows after the one before', async () => {
    await audit.append({ staffId: 's6', action: 'test.cp-a' });
    await audit.checkpoint();
    await audit.append({ staffId: 's6', action: 'test.cp-b' });
    await audit.checkpoint();
    await backup();
    const newest = cpsBackup.at(-1)!;
    const previous = cpsBackup.at(-2)!;
    await control.staffAuditCheckpoint.delete({ where: { seq: newest.seq } });
    await control.$executeRaw`DELETE FROM staff_audit_events WHERE seq > ${previous.headSeq}`;
    try {
      expect(await audit.verify()).toMatchObject({ valid: false });
    } finally {
      await restore();
    }
  });

  it('detects a rewritten chain whose hashes were all recomputed', async () => {
    await audit.append({
      staffId: 's7',
      action: 'test.rewrite',
      data: { v: 1 },
    });
    await audit.checkpoint();
    await backup();
    // An attacker with database access edits a row and recomputes every hash after it.
    const forged = new StaffAuditService(control, signer, kv, chainId);
    await control.staffAuditEvent.deleteMany({});
    try {
      for (const r of rowsBackup)
        await forged.append({
          staffId: r.staffId,
          action: r.action === 'test.rewrite' ? 'test.innocent' : r.action,
          targetType: (r.targetType ?? undefined) as never,
          targetId: r.targetId ?? undefined,
          data: r.data as Record<string, unknown>,
          ip: r.ip ?? undefined,
          requestId: r.requestId ?? undefined,
        });
      expect(await audit.verify()).toMatchObject({ valid: false });
    } finally {
      await restore();
    }
    expect(await audit.verify()).toMatchObject({ valid: true });
  });

  describe('the OpenBao head anchor', () => {
    const anchorPath = `audit/staff-audit-head/${chainId}`;
    const readAnchor = async () => (await kv.readSecretVersioned(anchorPath))!;

    it('two concurrent checkpoint writers leave the anchor on the newest checkpoint', async () => {
      for (let round = 0; round < 5; round++) {
        await audit.append({ staffId: 's8', action: `test.race${round}` });
        const other = new StaffAuditService(control, signer, kv, chainId);
        await Promise.all([
          audit.checkpoint(),
          other.checkpoint(),
          audit.checkpoint(),
        ]);
      }
      const newest = await control.staffAuditCheckpoint.findFirstOrThrow({
        orderBy: { seq: 'desc' },
      });
      const anchor = await readAnchor();
      expect(anchor.data.checkpointSeq).toBe(newest.seq.toString());
      expect(anchor.data.checkpointHash).toBe(newest.checkpointHash);
      expect(await audit.verify()).toMatchObject({ valid: true });
    });

    it('never moves the anchor backwards', async () => {
      await audit.append({ staffId: 's9', action: 'test.monotonic' });
      await audit.checkpoint();
      const before = await readAnchor();
      // A writer replaying an older checkpoint must not overwrite the newer anchor.
      const older = await control.staffAuditCheckpoint.findFirstOrThrow({
        where: { seq: { lt: BigInt(String(before.data.checkpointSeq)) } },
        orderBy: { seq: 'desc' },
      });
      await expect(audit.anchor(older)).resolves.toBe(false);
      expect((await readAnchor()).data.checkpointSeq).toBe(
        before.data.checkpointSeq,
      );
    });

    it('a stale anchor (more than one checkpoint behind, or old) fails verification', async () => {
      await audit.append({ staffId: 's10', action: 'test.stale-a' });
      await audit.checkpoint();
      const stale = await readAnchor();
      await audit.append({ staffId: 's10', action: 'test.stale-b' });
      await audit.checkpoint();
      await audit.append({ staffId: 's10', action: 'test.stale-c' });
      await audit.checkpoint();
      const current = await readAnchor();
      // Roll the anchor back by two checkpoints (an operator restoring an old OpenBao backup).
      await kv.writeSecretCas(anchorPath, stale.data, current.version);
      try {
        expect(await audit.verify()).toMatchObject({
          valid: false,
          reason: 'anchor_stale',
        });
      } finally {
        await kv.writeSecretCas(anchorPath, current.data, current.version + 1);
      }
      expect(await audit.verify()).toMatchObject({ valid: true });
    });

    it('one checkpoint behind is allowed only inside the lag window', async () => {
      await audit.append({ staffId: 's11', action: 'test.lag-a' });
      await audit.checkpoint();
      const behind = await readAnchor();
      await audit.append({ staffId: 's11', action: 'test.lag-b' });
      await audit.checkpoint();
      const current = await readAnchor();
      await kv.writeSecretCas(anchorPath, behind.data, current.version);
      try {
        expect(await audit.verify()).toMatchObject({ valid: true });
        const newest = await control.staffAuditCheckpoint.findFirstOrThrow({
          orderBy: { seq: 'desc' },
        });
        expect(
          await audit.verify(
            new Date(
              newest.createdAt.getTime() + StaffAuditService.ANCHOR_LAG_MS + 1,
            ),
          ),
        ).toMatchObject({
          valid: false,
          reason: 'anchor_stale',
        });
      } finally {
        await kv.writeSecretCas(anchorPath, current.data, current.version + 1);
      }
    });

    it('an anchor naming a deleted checkpoint fails verification', async () => {
      await audit.append({ staffId: 's12', action: 'test.deleted-cp' });
      await audit.checkpoint();
      await backup();
      await control.staffAuditCheckpoint.delete({
        where: { seq: cpsBackup.at(-1)!.seq },
      });
      try {
        expect(await audit.verify()).toMatchObject({
          valid: false,
          reason: 'anchored_checkpoint_missing',
        });
      } finally {
        await restore();
      }
      expect(await audit.verify()).toMatchObject({ valid: true });
    });
  });
});
