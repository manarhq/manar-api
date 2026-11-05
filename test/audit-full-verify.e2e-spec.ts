import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { AuditCheckpointService } from '../src/audit/checkpoint/audit-checkpoint.service';
import { CheckpointSigner } from '../src/audit/checkpoint/checkpoint-signer';
import { ControlSealMarkStore } from '../src/audit/checkpoint/seal-mark.store';
import {
  AuditFullVerifyService,
  composeVerifyResponse,
} from '../src/audit/audit-full-verify.service';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { OpenBaoKvClient } from '../src/openbao/openbao-kv.client';
import { fakeConfigService } from './support/audit-test-config';

/** Nightly full verification result, and the incremental-vs-full cost the console polls. */
describe('Audit full verification (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafka: KafkaPublisherService;
  let audit: AuditService;
  let checkpoints: AuditCheckpointService;
  let full: AuditFullVerifyService;
  const provisioned: { tenantId: string; databaseName: string }[] = [];
  const events = Number(process.env.AUDIT_FULL_VERIFY_EVENTS ?? 200);

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
    const signer = new CheckpointSigner(
      new OpenBaoKvClient(fakeConfigService()),
    );
    audit = new AuditService(kafka, signer, new ControlSealMarkStore(control));
    checkpoints = new AuditCheckpointService(
      signer,
      new ControlSealMarkStore(control),
    );
    full = new AuditFullVerifyService(control, manager, audit);
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
      await control.auditFullVerification.deleteMany({ where: { tenantId } });
      await control.auditSealMark.deleteMany({ where: { tenantId } });
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    await control.$disconnect();
  }, 60_000);

  async function tenantWithEvents(label: string) {
    const t = await manager.provisionTenant({
      slug: `fullv-${label}-${randomUUID().slice(0, 8)}`,
      name: `Audit full verify ${label}`,
    });
    provisioned.push({
      tenantId: t.id,
      databaseName: t.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(t.id);
    for (let done = 0; done < events; done += 500) {
      await Promise.all(
        Array.from({ length: Math.min(500, events - done) }, (_, i) =>
          audit.record(client, t.id, {
            eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
            actor: { type: 'agent', id: `agent-${i % 7}` },
            data: { i: done + i },
          }),
        ),
      );
    }
    await checkpoints.createCheckpoint(client, t.id);
    return { id: t.id, client };
  }

  async function addSealedEvent(t: {
    id: string;
    client: Parameters<typeof audit.record>[0];
  }) {
    await audit.record(t.client, t.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'agent', id: 'late' },
      data: {},
    });
    await checkpoints.createCheckpoint(t.client, t.id);
  }

  it('full vs incremental cost, and a tampered log is a failed full check; the incremental result after a tamper is pinned', async () => {
    const t = await tenantWithEvents('tamper');
    expect((await full.status(t.id)).state).toBe('never');

    let started = performance.now();
    expect((await full.verifyTenant(t.id)).valid).toBe(true);
    const fullMs = performance.now() - started;
    const status = await full.status(t.id);
    expect(status.state).toBe('passed');
    expect(status.lastFullVerifiedAt).toBeInstanceOf(Date);

    // The console's poll: incremental, resuming from the watermark the full walk just set.
    await addSealedEvent(t);
    started = performance.now();
    const incremental = await audit.verifyAuditChain(t.client, t.id, {
      incremental: true,
    });
    const incrementalMs = performance.now() - started;
    expect(incremental).toMatchObject({ valid: true });
    expect(incremental.valid && incremental.coveredFrom).toBeTruthy();
    process.stderr.write(
      JSON.stringify({
        events,
        fullVerifyMs: Math.round(fullMs),
        incrementalVerifyMs: Math.round(incrementalMs),
      }),
    );

    // Tamper with an event the watermark already covers. PINNED: the incremental check does not
    // re-walk covered events, so it still passes (the documented detection window); the next full
    // check finds it.
    await t.client
      .$executeRaw`UPDATE "audit_events" SET "data" = '{"tampered":true}'::jsonb WHERE "id" = (SELECT "id" FROM "audit_events" ORDER BY "sequence" LIMIT 1)`;
    const afterTamper = await audit.verifyAuditChain(t.client, t.id, {
      incremental: true,
    });
    expect(afterTamper.valid).toBe(true);
    expect(
      composeVerifyResponse(afterTamper, await full.status(t.id)),
    ).toMatchObject({
      valid: true,
      fullCheck: 'passed',
    });

    expect((await full.verifyTenant(t.id)).valid).toBe(false);
    const failed = await full.status(t.id);
    expect(failed.state).toBe('failed');
    expect(composeVerifyResponse(afterTamper, failed)).toMatchObject({
      valid: false,
      status: 'broken',
      fullCheck: 'failed',
    });
  }, 300_000);

  it("a run that cannot complete (timestamp 'infinity') is an error result: the old pass no longer counts", async () => {
    const t = await tenantWithEvents('infinity');
    expect((await full.verifyTenant(t.id)).valid).toBe(true);
    await addSealedEvent(t);
    await t.client
      .$executeRaw`UPDATE "audit_events" SET "timestamp" = 'infinity' WHERE "id" = (SELECT "id" FROM "audit_events" ORDER BY "sequence" LIMIT 1)`;

    await expect(full.verifyTenant(t.id)).rejects.toThrow();
    const s = await full.status(t.id);
    expect(s.state).toBe('error');
    const resumed = await audit.verifyAuditChain(t.client, t.id, {
      incremental: true,
    });
    expect(composeVerifyResponse(resumed, s)).toMatchObject({
      valid: false,
      status: 'partial',
      fullCheck: 'error',
    });
  }, 300_000);
});
