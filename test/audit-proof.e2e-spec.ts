import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { AuditCheckpointService } from '../src/audit/checkpoint/audit-checkpoint.service';
import {
  AuditCheckpointIndexError,
  AuditEventNotCheckpointedError,
  AuditEventNotFoundError,
  AuditProofService,
} from '../src/audit/checkpoint/audit-proof.service';
import { anchorDigestOf } from '../src/audit/checkpoint/checkpoint-format';
import {
  CheckpointSigner,
  NoCheckpointKeyError,
} from '../src/audit/checkpoint/checkpoint-signer';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { computeEventHash } from '../src/audit/audit-hash';
import { partitionFor } from '../src/audit/audit-partition';
import { verifyInclusion } from '../src/audit/merkle';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import {
  ControlSealMarkStore,
  SealContinuityError,
} from '../src/audit/checkpoint/seal-mark.store';
import { fakeConfigService } from './support/audit-test-config';

/** Inclusion proofs against SEALs, and SEAL checks inside `verifyAuditChain`. */
describe('Audit proofs (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafka: KafkaPublisherService;
  let audit: AuditService;
  let signer: CheckpointSigner;
  let checkpoints: AuditCheckpointService;
  let proofs: AuditProofService;
  const provisioned: { tenantId: string; databaseName: string }[] = [];

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    kafka = new KafkaPublisherService(fakeConfigService());
    await kafka.onModuleInit();
    signer = new CheckpointSigner(new OpenBaoKvClient(fakeConfigService()));
    audit = new AuditService(kafka, signer);
    checkpoints = new AuditCheckpointService(signer);
    proofs = new AuditProofService();
  }, 60_000);

  afterAll(async () => {
    await audit.onModuleDestroy();
    await kafka.onModuleDestroy();
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      const admin = new PgClient({
        connectionString: process.env.CONTROL_DATABASE_URL,
      });
      await admin.connect();
      await admin.query(
        `DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`,
      );
      await admin.end();
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    await control.$disconnect();
  }, 60_000);

  async function tenantWithEvents(label: string, count: number) {
    const t = await manager.provisionTenant({
      slug: `proof-${label}-${randomUUID().slice(0, 8)}`,
      name: `Audit proof ${label}`,
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    const events = await Promise.all(
      Array.from({ length: count }, (_, i) =>
        audit.record(client, t.id, {
          eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
          actor: { type: 'agent', id: `agent-${i % 7}` },
          data: { i },
        }),
      ),
    );
    return { id: t.id, client, events };
  }

  it('proves a checkpointed event: path to the root, root in a signed SEAL', async () => {
    const t = await tenantWithEvents('ok', 120);
    await checkpoints.createCheckpoint(t.client, t.id);
    const target = t.events[57]!;

    const proof = await proofs.proveEvent(t.client, target.id);

    expect(proof.leaf).toBe(target.eventHash);
    expect(proof.partition).toBe(target.partition);
    expect(proof.partitionSeq).toBe(target.partitionSeq);
    expect(verifyInclusion(proof.leaf, proof.proof, proof.root)).toBe(true);
    expect(
      proof.checkpoint.roots.some(
        (r) => r.partition === target.partition && r.root === proof.root,
      ),
    ).toBe(true);
    const { publicKeyPem } = await signer.publicKey(t.id);
    expect(
      CheckpointSigner.verify(
        proof.checkpoint.checkpointHash,
        proof.checkpoint.signature,
        publicKeyPem,
      ),
    ).toBe(true);
  }, 90_000);

  it('a deleted proof-index row is an integrity error, never "not sealed yet"', async () => {
    const t = await tenantWithEvents('index', 5);
    await checkpoints.createCheckpoint(t.client, t.id);
    await t.client.$executeRaw`DELETE FROM "audit_checkpoint_ranges"`;

    await expect(
      proofs.proveEvent(t.client, t.events[0]!.id),
    ).rejects.toBeInstanceOf(AuditCheckpointIndexError);
  }, 60_000);

  it('refuses to prove an event recorded after the last SEAL, or one that does not exist', async () => {
    const t = await tenantWithEvents('pending', 5);
    await checkpoints.createCheckpoint(t.client, t.id);
    const late = await audit.record(t.client, t.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'agent', id: 'agent-late' },
      data: {},
    });

    await expect(proofs.proveEvent(t.client, late.id)).rejects.toBeInstanceOf(
      AuditEventNotCheckpointedError,
    );
    await expect(
      proofs.proveEvent(t.client, randomUUID()),
    ).rejects.toBeInstanceOf(AuditEventNotFoundError);
  }, 60_000);

  it('verifyAuditChain checks the SEALs: an edited root is reported at its checkpoint', async () => {
    const t = await tenantWithEvents('tamper', 40);
    await checkpoints.createCheckpoint(t.client, t.id);
    expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
      valid: true,
    });

    await t.client.$executeRaw`
      UPDATE "audit_checkpoints"
      SET "roots" = jsonb_set("roots", '{0,root}', to_jsonb(repeat('0', 64)))
      WHERE "seq" = 1`;

    expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
      valid: false,
      brokenAt: 'checkpoint:1',
    });
  }, 60_000);

  it('verifyAuditChain rejects a SEAL whose signature is not the tenant key', async () => {
    const t = await tenantWithEvents('sig', 10);
    await checkpoints.createCheckpoint(t.client, t.id);
    const forged = Buffer.alloc(64, 1).toString('base64');
    await t.client
      .$executeRaw`UPDATE "audit_checkpoints" SET "signature" = ${forged} WHERE "seq" = 1`;

    expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
      valid: false,
      brokenAt: 'checkpoint:1',
    });
  }, 60_000);

  describe('deleting SEALs is detected', () => {
    const grace = AuditService.SEAL_GRACE_MS;
    // Everything recorded in these tests is seconds old; a zero grace period
    // treats it as old enough that it must already be sealed.
    beforeAll(() => {
      AuditService.SEAL_GRACE_MS = 0;
    });
    afterAll(() => {
      AuditService.SEAL_GRACE_MS = grace;
    });

    it('events no SEAL covers, older than the grace period, break verification', async () => {
      const t = await tenantWithEvents('unsealed', 12);
      const result = await audit.verifyAuditChain(t.client, t.id);
      expect(result.valid).toBe(false);
      expect((result as { brokenAt: string }).brokenAt).toMatch(
        /^unsealed:\d+$/,
      );
    }, 60_000);

    it('deleting the newest SEAL is reported', async () => {
      const t = await tenantWithEvents('tail', 10);
      await checkpoints.createCheckpoint(t.client, t.id);
      await audit.record(t.client, t.id, {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'agent', id: 'agent-0' },
        data: { late: true },
      });
      await checkpoints.createCheckpoint(t.client, t.id);
      expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
        valid: true,
      });

      await t.client
        .$executeRaw`DELETE FROM "audit_checkpoints" WHERE "seq" = 2`;

      const result = await audit.verifyAuditChain(t.client, t.id);
      expect(result.valid).toBe(false);
      expect((result as { brokenAt: string }).brokenAt).toMatch(/^unsealed:/);
    }, 60_000);

    it("forging an unsealed event's timestamp into the future does not hide it: freshness comes from the signed SEAL time", async () => {
      const t = await tenantWithEvents('future', 6);
      await checkpoints.createCheckpoint(t.client, t.id);
      const late = await audit.record(t.client, t.id, {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'agent', id: 'agent-future' },
        data: {},
      });
      // A consistent rewrite: timestamp a day ahead, hash recomputed, the
      // partition row updated. Only the signed SEAL time is left to judge by.
      const future = new Date(Date.now() + 86_400_000);
      const forged = computeEventHash({
        id: late.id,
        eventType: late.eventType,
        correlationId: late.correlationId,
        actor: late.actor,
        timestamp: future.toISOString(),
        data: late.data,
        previousHash: late.previousHash,
      });
      await t.client.$executeRaw`
        UPDATE "audit_events" SET "timestamp" = ${future}, "eventHash" = ${forged}
        WHERE "id" = ${late.id}`;
      await t.client.$executeRaw`
        UPDATE "audit_partition_state" SET "latestEventHash" = ${forged}
        WHERE "partition" = ${late.partition}`;

      expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
        valid: false,
        brokenAt: `unsealed:${late.partition}`,
      });
    }, 60_000);

    it('deleting every SEAL is reported', async () => {
      const t = await tenantWithEvents('all', 10);
      await checkpoints.createCheckpoint(t.client, t.id);
      await t.client.$executeRaw`DELETE FROM "audit_checkpoints"`;

      const result = await audit.verifyAuditChain(t.client, t.id);
      expect(result.valid).toBe(false);
      expect((result as { brokenAt: string }).brokenAt).toMatch(/^unsealed:/);
    }, 60_000);
  });

  it('deleting every SEAL is reported even inside the grace period, once the tenant key exists', async () => {
    const t = await tenantWithEvents('nokey', 8);
    await checkpoints.createCheckpoint(t.client, t.id);
    await t.client.$executeRaw`DELETE FROM "audit_checkpoints"`;

    const result = await audit.verifyAuditChain(t.client, t.id);
    expect(result.valid).toBe(false);
    expect((result as { brokenAt: string }).brokenAt).toMatch(/^unsealed:/);
  }, 60_000);

  it('wiping the whole log (events, SEALs, bookkeeping) is reported once the tenant key exists', async () => {
    const t = await tenantWithEvents('wipeall', 6);
    await checkpoints.createCheckpoint(t.client, t.id);
    await t.client.$executeRaw`DELETE FROM "audit_events"`;
    await t.client.$executeRaw`DELETE FROM "audit_checkpoints"`;
    await t.client.$executeRaw`DELETE FROM "audit_partition_state"`;

    const result = await audit.verifyAuditChain(t.client, t.id);
    expect(result.valid).toBe(false);
  }, 60_000);

  it("a row planted past a partition's recorded tail is reported", async () => {
    const t = await tenantWithEvents('planted', 3);
    const p = t.events[0]!.partition;
    const last = t.events
      .filter((e) => e.partition === p)
      .sort((a, b) => a.partitionSeq - b.partitionSeq)
      .at(-1)!;
    await t.client.$executeRaw`
      INSERT INTO "audit_events" ("id","eventType","correlationId","actor","timestamp","data","previousHash","eventHash","partition","partitionSeq")
      VALUES (${randomUUID()}, 'task.created', 'planted', '{"type":"system","id":"x"}'::jsonb, now(), '{}'::jsonb,
              ${last.eventHash}, ${'f'.repeat(64)}, ${p}, ${last.partitionSeq + 1})`;

    expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
      valid: false,
      brokenAt: `audit_partition_state:${p}`,
    });
  }, 60_000);

  it('looking up the key of a never-sealed tenant neither creates it nor breaks verification', async () => {
    const t = await tenantWithEvents('lookup', 4);
    await expect(signer.publicKey(t.id)).rejects.toBeInstanceOf(
      NoCheckpointKeyError,
    );
    expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
      valid: true,
    });
  }, 60_000);

  it('a forged (unsigned) retention anchor does not excuse deleted events', async () => {
    const t = await tenantWithEvents('anchor', 1);
    let n = 0;
    while (partitionFor({ type: 'agent', id: `agent-anchor-${n}` }, null) === 0)
      n += 1;
    const agent = `agent-anchor-${n}`;
    const events = [];
    for (let i = 0; i < 5; i += 1) {
      events.push(
        await audit.record(t.client, t.id, {
          eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
          actor: { type: 'agent', id: agent },
          data: { i },
        }),
      );
    }
    expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
      valid: true,
    });
    // Delete the first two events and plant the anchor retention would
    // write, but without the retention process's signature.
    await t.client.auditChainAnchor.create({
      data: {
        tenantId: t.id,
        partition: events[0]!.partition,
        anchorHash: events[1]!.eventHash,
        eventsPrunedCount: 2,
      },
    });
    await t.client.auditEvent.deleteMany({
      where: { id: { in: [events[0]!.id, events[1]!.id] } },
    });

    expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
      valid: false,
      brokenAt: events[2]!.id,
    });
  }, 60_000);

  it("deleting a whole partition (events and bookkeeping row) is caught by the last SEAL's heads", async () => {
    const t = await tenantWithEvents('wipe', 14);
    await checkpoints.createCheckpoint(t.client, t.id);
    const partition = t.events[0]!.partition;

    await t.client
      .$executeRaw`DELETE FROM "audit_events" WHERE "partition" = ${partition}`;
    await t.client
      .$executeRaw`DELETE FROM "audit_partition_state" WHERE "partition" = ${partition}`;

    expect(await audit.verifyAuditChain(t.client, t.id)).toEqual({
      valid: false,
      brokenAt: 'checkpoint:1',
    });
  }, 60_000);

  it('a partly pruned range still checks its sealed head: a consistent rewrite of the tail is caught', async () => {
    const t = await manager.provisionTenant({
      slug: `proof-head-${randomUUID().slice(0, 8)}`,
      name: 'Audit proof head',
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    const events = [];
    for (let i = 0; i < 5; i += 1) {
      events.push(
        await audit.record(client, t.id, {
          eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
          actor: { type: 'agent', id: 'agent-head' },
          data: { i },
        }),
      );
    }
    await checkpoints.createCheckpoint(client, t.id);
    const partition = events[0]!.partition;

    // Prune the first two as retention would: delete them, and write the
    // anchor naming the second, signed with the tenant key.
    const anchor = {
      tenantId: t.id,
      partition,
      anchorHash: events[1]!.eventHash,
      eventsPrunedCount: 2,
    };
    await client.auditChainAnchor.create({
      data: {
        ...anchor,
        signature: await signer.sign(t.id, anchorDigestOf(anchor)),
      },
    });
    await client.auditEvent.deleteMany({
      where: { id: { in: [events[0]!.id, events[1]!.id] } },
    });
    expect(await audit.verifyAuditChain(client, t.id)).toEqual({ valid: true });

    // Rewrite the tail consistently: new data, a correctly recomputed hash,
    // and the partition's bookkeeping row updated to match. The chain walk
    // alone cannot see this; the sealed head can.
    const tail = events[4]!;
    const forgedHash = computeEventHash({
      id: tail.id,
      eventType: tail.eventType,
      correlationId: tail.correlationId,
      actor: tail.actor,
      timestamp: tail.timestamp.toISOString(),
      data: { i: 4, forged: true },
      previousHash: tail.previousHash,
    });
    await client.$executeRaw`
      UPDATE "audit_events" SET "data" = '{"i":4,"forged":true}'::jsonb, "eventHash" = ${forgedHash}
      WHERE "id" = ${tail.id}`;
    await client.$executeRaw`
      UPDATE "audit_partition_state" SET "latestEventHash" = ${forgedHash}
      WHERE "partition" = ${partition}`;

    expect(await audit.verifyAuditChain(client, t.id)).toEqual({
      valid: false,
      brokenAt: 'checkpoint:1',
    });
  }, 60_000);

  describe('with the SEAL mark kept in the control database', () => {
    let marks: ControlSealMarkStore;
    let markedAudit: AuditService;
    let markedCheckpoints: AuditCheckpointService;
    beforeAll(() => {
      marks = new ControlSealMarkStore(control);
      markedAudit = new AuditService(kafka, signer, marks);
      markedCheckpoints = new AuditCheckpointService(signer, marks);
    });
    afterAll(async () => {
      await markedAudit.onModuleDestroy();
      await control.auditSealMark.deleteMany({
        where: { tenantId: { in: provisioned.map((p) => p.tenantId) } },
      });
    });

    it('deleting the newest SEALs is refused by the sealer and reported by verification', async () => {
      const t = await tenantWithEvents('mark', 6);
      await markedCheckpoints.createCheckpoint(t.client, t.id);
      await markedAudit.record(t.client, t.id, {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'agent', id: 'agent-0' },
        data: { late: true },
      });
      await markedCheckpoints.createCheckpoint(t.client, t.id);
      expect((await marks.get(t.id))?.sealSeq).toBe(2n);

      await t.client
        .$executeRaw`DELETE FROM "audit_checkpoint_ranges" WHERE "checkpointSeq" = 2`;
      await t.client
        .$executeRaw`DELETE FROM "audit_checkpoints" WHERE "seq" = 2`;

      await expect(
        markedCheckpoints.createCheckpoint(t.client, t.id),
      ).rejects.toBeInstanceOf(SealContinuityError);
      expect(await markedAudit.verifyAuditChain(t.client, t.id)).toEqual({
        valid: false,
        brokenAt: 'checkpoint:2',
      });
    }, 60_000);

    it('a watermark SEAL whose stored heads were edited is not trusted', async () => {
      const t = await tenantWithEvents('wmark', 4);
      await markedCheckpoints.createCheckpoint(t.client, t.id);
      expect(await markedAudit.verifyAuditChain(t.client, t.id)).toEqual({
        valid: true,
      });
      const newer = [];
      for (let i = 0; i < 3; i += 1) {
        newer.push(
          await markedAudit.record(t.client, t.id, {
            eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
            actor: { type: 'agent', id: 'agent-0' },
            data: { i },
          }),
        );
      }
      await t.client
        .$executeRaw`UPDATE "audit_events" SET "data" = '{"x":2}'::jsonb WHERE "id" = ${newer[0]!.id}`;
      // Point the watermark SEAL's heads at the current tail, so an
      // incremental run would start past the edited event.
      const tail = newer[2]!;
      await t.client.$executeRaw`
        UPDATE "audit_checkpoints"
        SET "partitionHeads" = jsonb_build_array(jsonb_build_object(
          'partition', ${tail.partition}::int, 'seq', ${String(tail.partitionSeq)}::text, 'eventHash', ${tail.eventHash}::text))
        WHERE "seq" = 1`;

      expect(
        await markedAudit.verifyAuditChain(t.client, t.id, {
          incremental: true,
        }),
      ).toEqual({ valid: false, brokenAt: 'checkpoint:1' });
    }, 60_000);

    it('incremental verification starts at the watermark and still checks everything after it', async () => {
      const t = await tenantWithEvents('incremental', 8);
      await markedCheckpoints.createCheckpoint(t.client, t.id);
      expect(await markedAudit.verifyAuditChain(t.client, t.id)).toEqual({
        valid: true,
      });
      expect((await marks.get(t.id))?.verified?.seq).toBe(1n);

      const later = [];
      for (let i = 0; i < 4; i += 1) {
        later.push(
          await markedAudit.record(t.client, t.id, {
            eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
            actor: { type: 'agent', id: 'agent-1' },
            data: { i },
          }),
        );
      }
      await markedCheckpoints.createCheckpoint(t.client, t.id);
      const resumed = await markedAudit.verifyAuditChain(t.client, t.id, {
        incremental: true,
      });
      expect(resumed.valid).toBe(true);
      expect(resumed.valid && resumed.coveredFrom).toBeTruthy();

      // The watermark is now SEAL 2. Events after it are still checked.
      const newer = [];
      for (let i = 0; i < 3; i += 1) {
        newer.push(
          await markedAudit.record(t.client, t.id, {
            eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
            actor: { type: 'agent', id: 'agent-1' },
            data: { newer: i },
          }),
        );
      }
      await markedCheckpoints.createCheckpoint(t.client, t.id);
      await t.client
        .$executeRaw`UPDATE "audit_events" SET "data" = '{"x":1}'::jsonb WHERE "id" = ${newer[1]!.id}`;
      expect(
        await markedAudit.verifyAuditChain(t.client, t.id, {
          incremental: true,
        }),
      ).toEqual({ valid: false, brokenAt: newer[1]!.id });
      // A full run re-walks everything and finds it too.
      expect(await markedAudit.verifyAuditChain(t.client, t.id)).toEqual({
        valid: false,
        brokenAt: newer[1]!.id,
      });
      expect(later).toHaveLength(4);
    }, 60_000);
  });
});
