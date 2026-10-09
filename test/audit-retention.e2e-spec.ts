import 'dotenv/config';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { NativeConnection, Worker } from '@temporalio/worker';
import { Client as TemporalClient, Connection } from '@temporalio/client';
import { AppConfig } from '../src/config/env.validation';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { AuditService } from '../src/audit/audit.service';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { WorkerAppModule } from '../src/temporal/worker-app.module';
import { ApprovalActivitiesFactory } from '../src/temporal/activities/approval.activities';
import { AuditRetentionActivitiesFactory } from '../src/temporal/activities/audit-retention.activities';
import { AuditRetentionWorkflow } from '../src/temporal/workflows/audit-retention.workflow';
import { DEFAULT_AUDIT_RETENTION_WINDOW_MS } from '../src/audit/retention/audit-retention.constants';

/**
 * Phase 9b (Retention, Section 48) — "seed events older than the window,
 * run `AuditRetentionWorkflow` (via Temporal's test environment... reuse
 * Phase 8's testing approach), confirm old events are gone, an anchor was
 * recorded, a `retention_executed` event exists, and `verifyAuditChain`
 * still reports valid for the pruned chain."
 *
 * Runs against real Postgres + a real local Temporal server
 * (`pnpm infra:up`'s `temporal` service) with a real in-process `Worker` —
 * the exact same "boot the real thing in-process" posture
 * `test/approvals.e2e-spec.ts` already establishes for `ApprovalWorkflow`,
 * reused here for `AuditRetentionWorkflow` registered off the same
 * combined workflow bundle `src/worker.main.ts` itself uses
 * (`src/temporal/workflows/index.ts`). No Keycloak/mTLS/HTTP app needed —
 * events are seeded directly via `AuditService`, mirroring
 * `test/audit-chain.e2e-spec.ts`'s lightweight pattern.
 */

function fakeConfigService(
  overrides: Partial<AppConfig> = {},
): ConfigService<AppConfig, true> {
  const values: AppConfig = {
    PORT: 3000,
    METRICS_PORT: 0,
    WORKER_METRICS_PORT: 0,
    NODE_ENV: 'test',
    LOG_LEVEL: 'info',
    CONTROL_DATABASE_URL: process.env.CONTROL_DATABASE_URL ?? '',
    TENANT_DB_BASE_URL: process.env.TENANT_DB_BASE_URL ?? '',
    TENANT_DB_CLIENT_CACHE_MAX: 50,
    TENANT_DB_CLIENT_IDLE_TTL_MS: 10 * 60 * 1000,
    TENANT_DB_CLIENT_REVALIDATE_MS: 5000,
    KEYCLOAK_BASE_URL: process.env.KEYCLOAK_BASE_URL ?? '',
    KEYCLOAK_ADMIN_USERNAME: process.env.KEYCLOAK_ADMIN_USERNAME ?? '',
    KEYCLOAK_ADMIN_PASSWORD: process.env.KEYCLOAK_ADMIN_PASSWORD ?? '',
    KEYCLOAK_ADMIN_CLIENT_ID:
      process.env.KEYCLOAK_ADMIN_CLIENT_ID ?? 'admin-cli',
    KEYCLOAK_CLIENT_ID: process.env.KEYCLOAK_CLIENT_ID ?? 'manar-api',
    MANAR_WEB_BASE_URL:
      process.env.MANAR_WEB_BASE_URL ?? 'http://localhost:3100',
    OPENBAO_ADDR: process.env.OPENBAO_ADDR ?? 'http://localhost:8200',
    OPENBAO_TOKEN: process.env.OPENBAO_TOKEN ?? 'manar-dev-root-token',
    OPENBAO_PKI_ROOT_PATH: process.env.OPENBAO_PKI_ROOT_PATH ?? 'pki',
    OPENBAO_PKI_INTERMEDIATE_PATH:
      process.env.OPENBAO_PKI_INTERMEDIATE_PATH ?? 'pki_int',
    OPENBAO_PKI_AGENT_ROLE: process.env.OPENBAO_PKI_AGENT_ROLE ?? 'manar-agent',
    OPENBAO_KV_MOUNT_PATH: process.env.OPENBAO_KV_MOUNT_PATH ?? 'secret',
    AGENT_MTLS_PORT: 3443,
    AGENT_MTLS_SERVER_CERT_PATH:
      process.env.AGENT_MTLS_SERVER_CERT_PATH ??
      'deploy/openbao/server-cert.pem',
    AGENT_MTLS_SERVER_KEY_PATH:
      process.env.AGENT_MTLS_SERVER_KEY_PATH ?? 'deploy/openbao/server-key.pem',
    AGENT_MTLS_CLIENT_CA_PATH:
      process.env.AGENT_MTLS_CLIENT_CA_PATH ?? 'deploy/openbao/ca-chain.pem',
    OPENFGA_API_URL: process.env.OPENFGA_API_URL ?? 'http://localhost:8080',
    OPENFGA_STORE_NAME: process.env.OPENFGA_STORE_NAME ?? 'manar',
    OPENFGA_STORE_ID: process.env.OPENFGA_STORE_ID,
    OPENFGA_CHECK_TIMEOUT_MS: 1000,
    OPENFGA_AUTHORIZATION_MODEL_ID: process.env.OPENFGA_AUTHORIZATION_MODEL_ID,
    OPENFGA_MODEL_FILE_PATH:
      process.env.OPENFGA_MODEL_FILE_PATH ??
      'src/authorization/model/manar.fga',
    TEMPORAL_ADDRESS: process.env.TEMPORAL_ADDRESS ?? 'localhost:7233',
    TEMPORAL_NAMESPACE: process.env.TEMPORAL_NAMESPACE ?? 'default',
    TEMPORAL_TASK_QUEUE: process.env.TEMPORAL_TASK_QUEUE ?? 'manar-approvals',
    APPROVAL_GRANT_SIGNING_SECRET:
      process.env.APPROVAL_GRANT_SIGNING_SECRET ??
      'test-approval-grant-signing-secret',
    PLATFORM_KILL_SWITCH_OPERATOR_TOKEN:
      process.env.PLATFORM_KILL_SWITCH_OPERATOR_TOKEN ??
      'test-platform-kill-switch-operator-token',
    MANAR_BFF_SERVICE_TOKEN:
      process.env.MANAR_BFF_SERVICE_TOKEN ?? 'test-manar-bff-service-token',
    PLATFORM_API_CLIENT_ID: 'manar-fleet',
    PLATFORM_API_ROLE: 'manar-platform-admin',
    FLEET_HEARTBEAT_INTERVAL_MINUTES: 5,
    FLEET_HEARTBEAT_KEY_PATH: 'fleet/heartbeat-signing-key',
    APPROVAL_GRANT_TTL_MS: 300_000,
    APPROVAL_REQUEST_TTL_MS: 1_800_000,
    APPROVAL_DECIDE_RESULT_TIMEOUT_MS: 120_000,
    KAFKA_BROKERS: process.env.KAFKA_BROKERS ?? 'localhost:29092',
    KAFKA_CLIENT_ID: 'audit-retention-e2e-test',
    KAFKA_AUDIT_TOPIC: process.env.KAFKA_AUDIT_TOPIC ?? 'manar.audit-events',
    OPENSEARCH_NODE: process.env.OPENSEARCH_NODE ?? 'http://localhost:9200',
    OPENSEARCH_AUDIT_INDEX:
      process.env.OPENSEARCH_AUDIT_INDEX ?? 'manar-audit-events',
    REDIS_URL: process.env.REDIS_URL ?? 'redis://localhost:6379',
    AI_ADVISORY_GRPC_TARGET:
      process.env.AI_ADVISORY_GRPC_TARGET ?? 'localhost:50051',
    AI_ADVISORY_TIMEOUT_MS: 2000,
    AI_ADVISORY_CIRCUIT_BREAKER_THRESHOLD: 3,
    AI_ADVISORY_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
    AI_ADVISORY_LONGFORM_TIMEOUT_MS: 30_000,
    AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_THRESHOLD: 3,
    AI_ADVISORY_LONGFORM_CIRCUIT_BREAKER_COOLDOWN_MS: 30_000,
    AI_ADVISORY_PROVIDER: 'ollama',
    PROMPT_INJECTION_BLOCK_THRESHOLD: 0.8,
    // Release 2026-11-11: mTLS to manar-ai is off by default; the
    // developer stack still uses manar-ai's plaintext listener.
    AI_ADVISORY_TLS_ENABLED: 'false',
    RATE_LIMIT_HUMAN_TTL_MS: 60_000,
    RATE_LIMIT_HUMAN_LIMIT: 300,
    RATE_LIMIT_AGENT_TTL_MS: 60_000,
    RATE_LIMIT_AGENT_LIMIT: 120,
    REDIS_TIMEOUT_MS: 1000,
    CORS_ALLOWED_ORIGINS: '*',
    WEBHOOK_SIGNATURE_TOLERANCE_MS: 300_000,
    WEBHOOK_DELIVERY_TASK_QUEUE: 'manar-webhooks',
    WEBHOOK_DELIVERY_TIMEOUT_MS: 10_000,
    WEBHOOK_DELIVERY_MAX_ATTEMPTS: 6,
    IDEMPOTENCY_KEY_TTL_MS: 86_400_000,
    IDEMPOTENCY_IN_PROGRESS_TTL_MS: 60_000,
    SSRF_ALLOWED_HOSTS: '127.0.0.1,localhost',
    SSRF_ALLOW_LOOPBACK: true,
    LLM_PROVIDER: 'ollama',
    LLM_OLLAMA_BASE_URL: 'http://localhost:11434/v1',
    LLM_MODEL: 'qwen3.5:9b',
    LLM_AZURE_OPENAI_API_VERSION: '2024-10-21',
    LLM_TASK_TOKEN_BUDGET: 200_000,
    LLM_UPSTREAM_TIMEOUT_MS: 180_000,
    ...overrides,
  };
  return {
    get: (key: keyof AppConfig) => values[key],
  } as unknown as ConfigService<AppConfig, true>;
}

function uniqueSlug(label: string): string {
  return `ret-${label}-${randomUUID().slice(0, 8)}`;
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

describe('Audit retention (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafkaPublisher: KafkaPublisherService;
  let auditService: AuditService;

  let workerModuleFixture: TestingModule;
  let temporalConnection: NativeConnection;
  let temporalWorker: Worker;
  let temporalWorkerRunPromise: Promise<void>;
  let temporalClientConnection: Connection;
  let temporalClient: TemporalClient;

  const taskQueue = `audit-retention-e2e-${randomUUID().slice(0, 8)}`;
  const provisioned: { tenantId: string; databaseName: string }[] = [];

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

    workerModuleFixture = await Test.createTestingModule({
      imports: [WorkerAppModule],
    }).compile();
    const activities = {
      ...workerModuleFixture.get(ApprovalActivitiesFactory).build(),
      ...workerModuleFixture.get(AuditRetentionActivitiesFactory).build(),
    };

    const temporalAddress = process.env.TEMPORAL_ADDRESS ?? 'localhost:7233';
    temporalConnection = await NativeConnection.connect({
      address: temporalAddress,
    });
    temporalWorker = await Worker.create({
      connection: temporalConnection,
      namespace: process.env.TEMPORAL_NAMESPACE ?? 'default',
      taskQueue,
      workflowsPath: join(process.cwd(), 'src/temporal/workflows/index.ts'),
      activities,
    });
    temporalWorkerRunPromise = temporalWorker.run();

    temporalClientConnection = await Connection.connect({
      address: temporalAddress,
    });
    temporalClient = new TemporalClient({
      connection: temporalClientConnection,
      namespace: process.env.TEMPORAL_NAMESPACE ?? 'default',
    });
  }, 60_000);

  afterAll(async () => {
    temporalWorker.shutdown();
    await temporalWorkerRunPromise;
    await temporalConnection.close();
    await temporalClientConnection.close();
    await workerModuleFixture.close();

    await kafkaPublisher.onModuleDestroy();
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      await dropRealDatabase(databaseName);
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    await control.$disconnect();
  }, 60_000);

  it('prunes aged-out events, anchors the chain, records audit.retention_executed, and keeps the chain verifiable', async () => {
    const tenant = await manager.provisionTenant({
      slug: uniqueSlug('t'),
      name: 'Retention Test Tenant',
    });
    if (!tenant.databaseBinding) throw new Error('expected database binding');
    provisioned.push({
      tenantId: tenant.id,
      databaseName: tenant.databaseBinding.databaseName,
    });
    const tenantClient = await manager.getClient(tenant.id);

    const oldIds: string[] = [];
    for (let i = 0; i < 5; i += 1) {
      const event = await auditService.record(tenantClient, tenant.id, {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'system', id: 'retention-test-old' },
        data: { i, age: 'old' },
      });
      oldIds.push(event.id);
    }
    // Backdate the "old" events directly (reaching around AuditService,
    // the same established pattern test/audit-chain.e2e-spec.ts's own
    // tamper tests use) — timestamp is the only field retention logic
    // filters on; the resulting hash/timestamp mismatch on these
    // soon-to-be-deleted rows is never observed by anything (they're
    // pruned before any verifyAuditChain call).
    const oldTimestamp = new Date(
      Date.now() - (DEFAULT_AUDIT_RETENTION_WINDOW_MS + 24 * 60 * 60 * 1000),
    );
    await tenantClient.auditEvent.updateMany({
      where: { id: { in: oldIds } },
      data: { timestamp: oldTimestamp },
    });
    const lastOldEvent = await tenantClient.auditEvent.findUniqueOrThrow({
      where: { id: oldIds[oldIds.length - 1] },
    });

    const newIds: string[] = [];
    for (let i = 0; i < 3; i += 1) {
      const event = await auditService.record(tenantClient, tenant.id, {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'system', id: 'retention-test-new' },
        data: { i, age: 'new' },
      });
      newIds.push(event.id);
    }
    const firstNewEventBefore = await tenantClient.auditEvent.findUniqueOrThrow(
      { where: { id: newIds[0] } },
    );
    // Sanity: the first "new" event really did chain off the last "old"
    // event at recording time (before backdating touched only `timestamp`,
    // never `previousHash`/`eventHash`).
    expect(firstNewEventBefore.previousHash).toBe(lastOldEvent.eventHash);

    expect(await tenantClient.auditEvent.count()).toBe(8);

    // No `worker.runUntil(...)` wrapper here — unlike `approval.workflow.spec.ts`'s
    // per-test worker, this suite's `temporalWorker` is already
    // continuously running in the background (`beforeAll`'s own
    // `temporalWorker.run()`, the same "boot the real thing once, reuse it
    // across every test" posture `test/approvals.e2e-spec.ts` establishes)
    // — calling `runUntil` on top of an already-running worker double-runs
    // it and crashes it.
    const result = await temporalClient.workflow.execute(
      AuditRetentionWorkflow,
      {
        workflowId: `audit-retention-${randomUUID()}`,
        taskQueue,
        args: [
          {
            tenantId: tenant.id,
            retentionWindowMs: DEFAULT_AUDIT_RETENTION_WINDOW_MS,
          },
        ],
      },
    );

    expect(result.prunedCount).toBe(5);
    expect(result.anchorHash).toBe(lastOldEvent.eventHash);
    expect(result.retentionEventId).toBeTruthy();

    // Old events are gone.
    const remainingOldCount = await tenantClient.auditEvent.count({
      where: { id: { in: oldIds } },
    });
    expect(remainingOldCount).toBe(0);

    // New events survived, untouched.
    const remainingNewCount = await tenantClient.auditEvent.count({
      where: { id: { in: newIds } },
    });
    expect(remainingNewCount).toBe(3);

    // An anchor was recorded.
    const anchors = await tenantClient.auditChainAnchor.findMany({
      where: { tenantId: tenant.id },
    });
    expect(anchors).toHaveLength(1);
    expect(anchors[0]!.anchorHash).toBe(lastOldEvent.eventHash);
    expect(anchors[0]!.eventsPrunedCount).toBe(5);

    // A retention_executed event exists and is now the chain tail.
    const retentionEvent = await tenantClient.auditEvent.findUnique({
      where: { id: result.retentionEventId! },
    });
    expect(retentionEvent).not.toBeNull();
    expect(retentionEvent?.eventType).toBe('audit.retention_executed');
    expect(
      (retentionEvent?.data as { eventsPrunedCount?: number })
        ?.eventsPrunedCount,
    ).toBe(5);

    const chainState = await tenantClient.auditChainState.findUnique({
      where: { id: 'singleton' },
    });
    expect(chainState?.latestEventId).toBe(result.retentionEventId);

    // The pruned chain still verifies — anchor-aware verifyAuditChain.
    const verifyResult = await auditService.verifyAuditChain(tenantClient);
    expect(verifyResult).toEqual({ valid: true });

    expect(await tenantClient.auditEvent.count()).toBe(4); // 3 new + 1 retention_executed
  }, 60_000);

  it('a retention run that finds nothing old enough is a genuine no-op', async () => {
    const tenant = await manager.provisionTenant({
      slug: uniqueSlug('noop'),
      name: 'Retention No-op Test Tenant',
    });
    if (!tenant.databaseBinding) throw new Error('expected database binding');
    provisioned.push({
      tenantId: tenant.id,
      databaseName: tenant.databaseBinding.databaseName,
    });
    const tenantClient = await manager.getClient(tenant.id);

    await auditService.record(tenantClient, tenant.id, {
      eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
      actor: { type: 'system', id: 'retention-noop-test' },
      data: { fresh: true },
    });

    const result = await temporalClient.workflow.execute(
      AuditRetentionWorkflow,
      {
        workflowId: `audit-retention-noop-${randomUUID()}`,
        taskQueue,
        args: [
          {
            tenantId: tenant.id,
            retentionWindowMs: DEFAULT_AUDIT_RETENTION_WINDOW_MS,
          },
        ],
      },
    );

    expect(result).toEqual({
      prunedCount: 0,
      anchorHash: null,
      retentionEventId: null,
    });
    expect(await tenantClient.auditEvent.count()).toBe(1);
    expect(
      await tenantClient.auditChainAnchor.count({
        where: { tenantId: tenant.id },
      }),
    ).toBe(0);
  }, 30_000);
});
