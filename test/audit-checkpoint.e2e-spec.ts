import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { AuditCheckpointService } from '../src/audit/checkpoint/audit-checkpoint.service';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { merkleRoot } from '../src/audit/merkle';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import { fakeConfigService } from './support/audit-test-config';

/**
 * SEALs (signed audit checkpoints) against a real tenant Postgres database
 * and the real OpenBao KV holding each tenant's Ed25519 key.
 */
describe('Audit checkpoints (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafka: KafkaPublisherService;
  let audit: AuditService;
  let signer: CheckpointSigner;
  let checkpoints: AuditCheckpointService;
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
    audit = new AuditService(kafka);
    signer = new CheckpointSigner(new OpenBaoKvClient(fakeConfigService()));
    checkpoints = new AuditCheckpointService(signer);
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

  async function tenant(label: string) {
    const t = await manager.provisionTenant({
      slug: `seal-${label}-${randomUUID().slice(0, 8)}`,
      name: `Audit SEAL ${label}`,
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    return { id: t.id, client: await manager.getClient(t.id) };
  }

  async function recordMany(
    t: {
      id: string;
      client: Awaited<ReturnType<TenantDatabaseManager['getClient']>>;
    },
    count: number,
    offset = 0,
  ) {
    await Promise.all(
      Array.from({ length: count }, (_, i) =>
        audit.record(t.client, t.id, {
          eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
          actor: { type: 'agent', id: `agent-${(i + offset) % 40}` },
          data: { i: i + offset },
        }),
      ),
    );
  }

  it('seals 200 events: signed, chained, with each root over its partition range', async () => {
    const t = await tenant('first');
    await recordMany(t, 200);

    const first = await checkpoints.createCheckpoint(t.client, t.id);
    expect(first).not.toBeNull();
    expect(first!.seq).toBe(1n);
    expect(first!.previousCheckpointHash).toBeNull();

    const { publicKeyPem, keyId } = await signer.publicKey(t.id);
    expect(first!.keyId).toBe(keyId);
    expect(
      CheckpointSigner.verify(
        first!.checkpointHash,
        first!.signature,
        publicKeyPem,
      ),
    ).toBe(true);

    const roots = first!.roots as {
      partition: number;
      fromSeq: string;
      toSeq: string;
      root: string;
    }[];
    let covered = 0;
    for (const r of roots) {
      const events = await t.client.auditEvent.findMany({
        where: {
          partition: r.partition,
          partitionSeq: { gte: BigInt(r.fromSeq), lte: BigInt(r.toSeq) },
        },
        orderBy: { partitionSeq: 'asc' },
      });
      expect(r.root).toBe(merkleRoot(events.map((e) => e.eventHash)));
      covered += events.length;
    }
    expect(covered).toBe(200);

    // Nothing new: no checkpoint.
    expect(await checkpoints.createCheckpoint(t.client, t.id)).toBeNull();

    await recordMany(t, 50, 200);
    const second = await checkpoints.createCheckpoint(t.client, t.id);
    expect(second!.seq).toBe(2n);
    expect(second!.previousCheckpointHash).toBe(first!.checkpointHash);
    const secondRoots = second!.roots as {
      partition: number;
      fromSeq: string;
    }[];
    for (const r of secondRoots) {
      const head = (
        first!.partitionHeads as { partition: number; seq: string }[]
      ).find((h) => h.partition === r.partition);
      expect(BigInt(r.fromSeq)).toBe(BigInt(head?.seq ?? '0') + 1n);
    }
  }, 90_000);

  it('two concurrent createCheckpoint calls write one checkpoint', async () => {
    const t = await tenant('race');
    await recordMany(t, 30);

    const results = await Promise.all([
      checkpoints.createCheckpoint(t.client, t.id),
      checkpoints.createCheckpoint(t.client, t.id),
    ]);

    expect(results.filter((r) => r !== null)).toHaveLength(1);
    expect(await t.client.auditCheckpoint.count()).toBe(1);
  }, 60_000);
});
