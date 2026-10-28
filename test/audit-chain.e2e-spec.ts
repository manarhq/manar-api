import 'dotenv/config';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  cpSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { PrismaPg } from '@prisma/adapter-pg';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fakeConfigService } from './support/audit-test-config';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import {
  AuditService,
  type AuditEventRecord,
} from '../src/audit/audit.service';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { computeEventHash } from '../src/audit/audit-hash';
import { partitionFor } from '../src/audit/audit-partition';
import { PrismaClient as TenantPrismaClient } from '../src/generated/tenant-client/client';

/**
 * Phase 9a's core `AuditService` invariants — the design spec's mandatory
 * scenarios that don't require a full HTTP app (those live in
 * `test/audit-retrofit.e2e-spec.ts`): chain-of-N verifies, tampering is
 * detected and correctly located, concurrent `record()` calls never fork
 * the chain. Runs against a real tenant Postgres database
 * (`TenantDatabaseManager.provisionTenant`, the same lightweight pattern
 * `src/database/tenant-database-manager.spec.ts` already establishes) —
 * no Keycloak/mTLS/Temporal needed for any of this.
 */

function uniqueSlug(label: string): string {
  return `audit-${label}-${randomUUID().slice(0, 8)}`;
}

async function dropRealDatabase(databaseName: string): Promise<void> {
  const admin = new PgClient({
    connectionString: process.env.CONTROL_DATABASE_URL,
  });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  } finally {
    await admin.end();
  }
}

async function cleanupTenant(
  control: ControlPrismaService,
  tenantId: string,
  databaseName: string,
): Promise<void> {
  await dropRealDatabase(databaseName);
  await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
  await control.secretReference.deleteMany({ where: { tenantId } });
  await control.tenant.deleteMany({ where: { id: tenantId } });
}

describe('Audit chain (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafkaPublisher: KafkaPublisherService;
  let auditService: AuditService;

  const provisioned: { tenantId: string; databaseName: string }[] = [];

  type ProvisionedTenant = Awaited<
    ReturnType<TenantDatabaseManager['provisionTenant']>
  >;
  let tenantGrowth: ProvisionedTenant;
  let tenantTamperData: ProvisionedTenant;
  let tenantTamperHash: ProvisionedTenant;

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    kafkaPublisher = new KafkaPublisherService(fakeConfigService());
    await kafkaPublisher.onModuleInit();
    auditService = new AuditService(kafkaPublisher);

    tenantGrowth = await manager.provisionTenant({
      slug: uniqueSlug('growth'),
      name: 'Audit Chain Growth Tenant',
    });
    tenantTamperData = await manager.provisionTenant({
      slug: uniqueSlug('tamper-data'),
      name: 'Audit Chain Tamper-Data Tenant',
    });
    tenantTamperHash = await manager.provisionTenant({
      slug: uniqueSlug('tamper-hash'),
      name: 'Audit Chain Tamper-Hash Tenant',
    });

    for (const t of [tenantGrowth, tenantTamperData, tenantTamperHash]) {
      if (!t.databaseBinding) {
        throw new Error(
          'Expected provisioned tenant to have a database binding',
        );
      }
      provisioned.push({
        tenantId: t.id,
        databaseName: t.databaseBinding.databaseName,
      });
    }
  }, 90_000);

  afterAll(async () => {
    await kafkaPublisher.onModuleDestroy();
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      await cleanupTenant(control, tenantId, databaseName);
    }
    await control.$disconnect();
  }, 60_000);

  it('records a chain of N events that all verify successfully', async () => {
    const tenantClient = await manager.getClient(tenantGrowth.id);

    for (let i = 0; i < 10; i += 1) {
      await auditService.record(tenantClient, tenantGrowth.id, {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'system', id: 'audit-chain-test' },
        data: { i },
      });
    }

    const result = await auditService.verifyAuditChain(tenantClient);
    expect(result).toEqual({ valid: true });

    const count = await tenantClient.auditEvent.count();
    expect(count).toBe(10);

    const events = await tenantClient.auditEvent.findMany({
      orderBy: { sequence: 'asc' },
    });
    expect(events[0]?.previousHash).toBeNull();
    for (let i = 1; i < events.length; i += 1) {
      expect(events[i]?.previousHash).toBe(events[i - 1]?.eventHash);
    }
  }, 30_000);

  it('concurrent record() calls never fork the chain — no two events share a previousHash, and the chain stays linear and verifies', async () => {
    const tenantClient = await manager.getClient(tenantGrowth.id);
    const before = await tenantClient.auditEvent.count();

    const concurrency = 20;
    await Promise.all(
      Array.from({ length: concurrency }, (_, i) =>
        auditService.record(tenantClient, tenantGrowth.id, {
          eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
          actor: { type: 'system', id: `concurrent-${i}` },
          data: { i },
        }),
      ),
    );

    const after = await tenantClient.auditEvent.count();
    expect(after).toBe(before + concurrency);

    const result = await auditService.verifyAuditChain(tenantClient);
    expect(result).toEqual({ valid: true });

    const events = await tenantClient.auditEvent.findMany({
      orderBy: { sequence: 'asc' },
    });
    const nonNullPreviousHashes = events
      .map((e) => e.previousHash)
      .filter((h): h is string => h !== null);
    // No fork: every non-null previousHash appears at most once across the
    // whole chain — if two events had computed the same previousHash (a
    // fork), this set would be smaller than the array.
    expect(new Set(nonNullPreviousHashes).size).toBe(
      nonNullPreviousHashes.length,
    );
    // Exactly one event per partition has previousHash === null (that
    // partition's first) — a second null in a partition would be a fork.
    const partitions = new Set(events.map((e) => e.partition));
    expect(events.filter((e) => e.previousHash === null)).toHaveLength(
      partitions.size,
    );
  }, 30_000);

  it('tampering a stored AuditEvent.data directly fails verification and reports exactly where', async () => {
    const tenantClient = await manager.getClient(tenantTamperData.id);

    const first = await auditService.record(tenantClient, tenantTamperData.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'system', id: 'tamper-test' },
      data: { original: true },
    });
    await auditService.record(tenantClient, tenantTamperData.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'system', id: 'tamper-test' },
      data: { seq: 2 },
    });
    await auditService.record(tenantClient, tenantTamperData.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'system', id: 'tamper-test' },
      data: { seq: 3 },
    });

    // Verifies cleanly before tampering.
    expect(await auditService.verifyAuditChain(tenantClient)).toEqual({
      valid: true,
    });

    // Modify an OLD event's data directly in the database — no application
    // code path does this; this is deliberately reaching around
    // AuditService to simulate a tamper.
    await tenantClient.auditEvent.update({
      where: { id: first.id },
      data: { data: { original: false, tampered: true } },
    });

    const result = await auditService.verifyAuditChain(tenantClient);
    expect(result).toEqual({ valid: false, brokenAt: first.id });
  }, 30_000);

  it('tampering a stored AuditEvent.eventHash directly fails verification and reports exactly where', async () => {
    const tenantClient = await manager.getClient(tenantTamperHash.id);

    await auditService.record(tenantClient, tenantTamperHash.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'system', id: 'tamper-test' },
      data: { seq: 1 },
    });
    const second = await auditService.record(
      tenantClient,
      tenantTamperHash.id,
      {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'system', id: 'tamper-test' },
        data: { seq: 2 },
      },
    );
    await auditService.record(tenantClient, tenantTamperHash.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'system', id: 'tamper-test' },
      data: { seq: 3 },
    });

    expect(await auditService.verifyAuditChain(tenantClient)).toEqual({
      valid: true,
    });

    await tenantClient.auditEvent.update({
      where: { id: second.id },
      data: { eventHash: 'a'.repeat(64) },
    });

    const result = await auditService.verifyAuditChain(tenantClient);
    expect(result).toEqual({ valid: false, brokenAt: second.id });
  }, 30_000);

  it('concurrent writers from two app instances keep every partition valid', async () => {
    // A second manager and service: a separate connection pool and batcher,
    // the same as a second API replica.
    const manager2 = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    const service2 = new AuditService(kafkaPublisher);
    const tenant = await manager.provisionTenant({
      slug: uniqueSlug('replicas'),
      name: 'Audit Two Replicas Tenant',
    });
    provisioned.push({
      tenantId: tenant.id,
      databaseName: tenant.databaseBinding!.databaseName,
    });
    const clientA = await manager.getClient(tenant.id);
    const clientB = await manager2.getClient(tenant.id);

    // Ten waves of 100: each wave makes both "replicas" flush a batch at the
    // same moment onto the same partitions, so their transactions overlap.
    for (let wave = 0; wave < 10; wave += 1) {
      await Promise.all(
        Array.from({ length: 100 }, (_, j) => {
          const i = wave * 100 + j;
          return (i % 2 === 0 ? auditService : service2).record(
            i % 2 === 0 ? clientA : clientB,
            tenant.id,
            {
              eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
              actor: { type: 'agent', id: `agent-${i % 50}` },
              data: { i },
            },
          );
        }),
      );
    }

    expect(await auditService.verifyAuditChain(clientA)).toEqual({
      valid: true,
    });
    const states = await clientA.auditPartitionState.findMany();
    expect(states.reduce((sum, s) => sum + s.eventCount, 0)).toBe(1000);
    expect(states.length).toBe(
      new Set(
        Array.from({ length: 50 }, (_, i) =>
          partitionFor({ type: 'agent', id: `agent-${i}` }, null),
        ),
      ).size,
    );
    await service2.onModuleDestroy();
    await manager2.onModuleDestroy();
  }, 90_000);

  it('an event Postgres refuses (U+0000 in data) fails alone; its batch-mates commit', async () => {
    const tenant = await manager.provisionTenant({
      slug: uniqueSlug('poison'),
      name: 'Audit Poison Event Tenant',
    });
    provisioned.push({
      tenantId: tenant.id,
      databaseName: tenant.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(tenant.id);
    const record = (data: unknown) =>
      auditService.record(client, tenant.id, {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'agent', id: 'agent-poison' },
        data,
      });

    const results = await Promise.allSettled([
      record({ n: 1 }),
      record({ text: 'bad\u0000' }),
      record({ n: 3 }),
    ]);

    expect(results.map((r) => r.status)).toEqual([
      'fulfilled',
      'rejected',
      'fulfilled',
    ]);
    expect(await client.auditEvent.count()).toBe(2);
    expect(await auditService.verifyAuditChain(client)).toEqual({
      valid: true,
    });
  }, 60_000);

  it('tampering a middle event in one partition reports that event', async () => {
    const tenant = await manager.provisionTenant({
      slug: uniqueSlug('tamper-partition'),
      name: 'Audit Partition Tamper Tenant',
    });
    provisioned.push({
      tenantId: tenant.id,
      databaseName: tenant.databaseBinding!.databaseName,
    });
    const client = await manager.getClient(tenant.id);
    const recorded: AuditEventRecord[] = [];
    for (let i = 0; i < 30; i += 1) {
      recorded.push(
        await auditService.record(client, tenant.id, {
          eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
          actor: { type: 'agent', id: `agent-${i % 3}` },
          data: { i },
        }),
      );
    }
    const target = recorded.filter(
      (e) => e.partition === recorded[0]!.partition,
    )[5]!;

    await client.$executeRaw`UPDATE "audit_events" SET "data" = '{"tampered":true}'::jsonb WHERE "id" = ${target.id}`;

    expect(await auditService.verifyAuditChain(client)).toEqual({
      valid: false,
      brokenAt: target.id,
    });
  }, 60_000);

  it('a pre-migration single chain still verifies as partition 0, and keeps growing', async () => {
    const exec = promisify(execFile);
    const databaseName = `audit_legacy_${randomUUID().slice(0, 8)}`;
    const admin = new PgClient({
      connectionString: process.env.CONTROL_DATABASE_URL,
    });
    await admin.connect();
    await admin.query(`CREATE DATABASE "${databaseName}"`);
    await admin.end();
    const url = new URL(process.env.TENANT_DB_BASE_URL ?? '');
    url.pathname = `/${databaseName}`;

    const dir = mkdtempSync(path.join(tmpdir(), 'audit-legacy-'));
    const migrationsSrc = path.resolve('prisma/tenant/migrations');
    const partitionsMigration = '20261028100000_audit_partitions';
    for (const entry of readdirSync(migrationsSrc)) {
      if (entry === partitionsMigration) continue;
      cpSync(
        path.join(migrationsSrc, entry),
        path.join(dir, 'migrations', entry),
        {
          recursive: true,
        },
      );
    }
    writeFileSync(
      path.join(dir, 'prisma.config.mjs'),
      `export default { schema: ${JSON.stringify(path.resolve('prisma/tenant.prisma'))}, migrations: { path: ${JSON.stringify(path.join(dir, 'migrations'))} }, datasource: { url: process.env.DATABASE_URL } };`,
    );
    const prismaCli = path.resolve('node_modules/prisma/build/index.js');
    const deploy = () =>
      exec(
        process.execPath,
        [
          prismaCli,
          'migrate',
          'deploy',
          '--config',
          path.join(dir, 'prisma.config.mjs'),
        ],
        { env: { ...process.env, DATABASE_URL: url.toString() } },
      );

    try {
      await deploy();

      // 20 events in the old layout: one chain, linked by "sequence".
      const pg = new PgClient({ connectionString: url.toString() });
      await pg.connect();
      let previousHash: string | null = null;
      let lastId = '';
      for (let i = 0; i < 20; i += 1) {
        const id = randomUUID();
        const timestamp = new Date(Date.UTC(2026, 9, 1, 0, 0, i));
        const content = {
          id,
          eventType: 'task.created',
          correlationId: `legacy-${i}`,
          actor: { type: 'system', id: `system:legacy-${i}` },
          timestamp: timestamp.toISOString(),
          data: { i },
          previousHash,
        };
        const eventHash = computeEventHash(content);
        await pg.query(
          'INSERT INTO "audit_events" ("id","eventType","correlationId","actor","timestamp","data","previousHash","eventHash") VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
          [
            id,
            content.eventType,
            content.correlationId,
            content.actor,
            // UTC text: a Date would be stored in the host's local time.
            content.timestamp,
            content.data,
            previousHash,
            eventHash,
          ],
        );
        previousHash = eventHash;
        lastId = id;
      }
      await pg.query(
        'INSERT INTO "audit_chain_state" ("id","latestEventId","latestEventHash","eventCount","updatedAt") VALUES (\'singleton\',$1,$2,20,now())',
        [lastId, previousHash],
      );
      await pg.end();

      cpSync(
        path.join(migrationsSrc, partitionsMigration),
        path.join(dir, 'migrations', partitionsMigration),
        { recursive: true },
      );
      await deploy();

      const client = new TenantPrismaClient({
        adapter: new PrismaPg({ connectionString: url.toString() }),
      });
      try {
        expect(await auditService.verifyAuditChain(client)).toEqual({
          valid: true,
        });
        const state = await client.auditPartitionState.findUnique({
          where: { partition: 0 },
        });
        expect(state?.latestSeq).toBe(20n);
        expect(state?.latestEventHash).toBe(previousHash);

        // A new event for a system actor that lands in partition 0 chains on the old tail.
        let n = 0;
        while (
          partitionFor({ type: 'system', id: `system:new-${n}` }, null) !== 0
        )
          n += 1;
        const next = await auditService.record(client, 'legacy-tenant', {
          eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
          actor: { type: 'system', id: `system:new-${n}` },
          data: {},
        });
        expect(next.previousHash).toBe(previousHash);
        expect(next.partitionSeq).toBe(21n);
        expect(await auditService.verifyAuditChain(client)).toEqual({
          valid: true,
        });
      } finally {
        await client.$disconnect();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
      await dropRealDatabase(databaseName);
    }
  }, 120_000);
});
