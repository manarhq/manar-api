import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { AuditCheckpointService } from '../src/audit/checkpoint/audit-checkpoint.service';
import {
  AuditEventNotCheckpointedError,
  AuditEventNotFoundError,
  AuditProofService,
} from '../src/audit/checkpoint/audit-proof.service';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { computeEventHash } from '../src/audit/audit-hash';
import { verifyInclusion } from '../src/audit/merkle';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
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
    expect(proof.partitionSeq).toBe(target.partitionSeq.toString());
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

    it('deleting every SEAL is reported', async () => {
      const t = await tenantWithEvents('all', 10);
      await checkpoints.createCheckpoint(t.client, t.id);
      await t.client.$executeRaw`DELETE FROM "audit_checkpoints"`;

      const result = await audit.verifyAuditChain(t.client, t.id);
      expect(result.valid).toBe(false);
      expect((result as { brokenAt: string }).brokenAt).toMatch(/^unsealed:/);
    }, 60_000);
  });

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

    // Prune the first two as retention would: delete them, anchor the second.
    await client.auditChainAnchor.create({
      data: {
        tenantId: t.id,
        partition,
        anchorHash: events[1]!.eventHash,
        eventsPrunedCount: 2,
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
});
