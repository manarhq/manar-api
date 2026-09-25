import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import { KafkaJS } from '@confluentinc/kafka-javascript';
import { AppConfig } from '../src/config/env.validation';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { AuditService } from '../src/audit/audit.service';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';
import { OpenSearchIndexService } from '../src/audit/opensearch/opensearch-client.service';
import { AuditReindexService } from '../src/audit/opensearch/audit-reindex.service';
import { AuditIndexerService } from '../src/audit/opensearch/audit-indexer.service';
import { RedisPubSubService } from '../src/audit/live/redis-pubsub.service';
import { AUDIT_EVENTS_TOPIC } from '../src/audit/domain-event-envelope';

/**
 * Phase 9b (Section 45) — "OpenSearch reindex is real: empty the index,
 * run `audit:reindex`, confirm every Postgres `AuditEvent` is now
 * searchable/present" and "Kafka redelivery of the same `eventId` doesn't
 * double-index (extends 9a's idempotency test to the real indexer, not a
 * throwaway test consumer)." Runs against real Postgres/Kafka/OpenSearch
 * (`pnpm infra:up`), the same lightweight `fakeConfigService` pattern
 * `test/audit-chain.e2e-spec.ts` already establishes — no Keycloak/mTLS/
 * Temporal needed for either scenario.
 */

function fakeConfigService(
  overrides: Partial<AppConfig> = {},
): ConfigService<AppConfig, true> {
  const values: AppConfig = {
    PORT: 3000,
    NODE_ENV: 'test',
    LOG_LEVEL: 'info',
    CONTROL_DATABASE_URL: process.env.CONTROL_DATABASE_URL ?? '',
    TENANT_DB_BASE_URL: process.env.TENANT_DB_BASE_URL ?? '',
    TENANT_DB_CLIENT_CACHE_MAX: 50,
    TENANT_DB_CLIENT_IDLE_TTL_MS: 10 * 60 * 1000,
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
    APPROVAL_GRANT_TTL_MS: 300_000,
    APPROVAL_REQUEST_TTL_MS: 1_800_000,
    APPROVAL_DECIDE_RESULT_TIMEOUT_MS: 120_000,
    KAFKA_BROKERS: process.env.KAFKA_BROKERS ?? 'localhost:29092',
    KAFKA_CLIENT_ID: 'audit-opensearch-indexing-e2e-test',
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
    CORS_ALLOWED_ORIGINS: '*',
    WEBHOOK_SIGNATURE_TOLERANCE_MS: 300_000,
    WEBHOOK_DELIVERY_TASK_QUEUE: 'manar-webhooks',
    WEBHOOK_DELIVERY_TIMEOUT_MS: 10_000,
    WEBHOOK_DELIVERY_MAX_ATTEMPTS: 6,
    IDEMPOTENCY_KEY_TTL_MS: 86_400_000,
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
  return `os-${label}-${randomUUID().slice(0, 8)}`;
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

describe('OpenSearch audit-event indexing (e2e)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;
  let kafkaPublisher: KafkaPublisherService;
  let auditService: AuditService;
  let openSearchIndexService: OpenSearchIndexService;
  let auditReindexService: AuditReindexService;

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
    openSearchIndexService = new OpenSearchIndexService(fakeConfigService());
    await openSearchIndexService.onModuleInit();
    auditReindexService = new AuditReindexService(openSearchIndexService);
  }, 60_000);

  afterAll(async () => {
    await kafkaPublisher.onModuleDestroy();
    await openSearchIndexService.onModuleDestroy();
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      await dropRealDatabase(databaseName);
      await control.tenantDatabaseBinding.deleteMany({ where: { tenantId } });
      await control.secretReference.deleteMany({ where: { tenantId } });
      await control.tenant.deleteMany({ where: { id: tenantId } });
    }
    await control.$disconnect();
  }, 60_000);

  it('audit:reindex fully reconstructs the OpenSearch index from Postgres alone after the index is emptied', async () => {
    const tenant = await manager.provisionTenant({
      slug: uniqueSlug('reindex'),
      name: 'OpenSearch Reindex Test Tenant',
    });
    if (!tenant.databaseBinding) throw new Error('expected database binding');
    provisioned.push({
      tenantId: tenant.id,
      databaseName: tenant.databaseBinding.databaseName,
    });
    const tenantClient = await manager.getClient(tenant.id);

    const recorded: string[] = [];
    for (let i = 0; i < 12; i += 1) {
      const event = await auditService.record(tenantClient, tenant.id, {
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        actor: { type: 'system', id: 'reindex-test' },
        data: { i },
      });
      recorded.push(event.id);
    }

    // Give any live Kafka-driven indexer(s) racing this test (every other
    // concurrently-running e2e file that boots `AppModule` runs its own
    // `AuditIndexerService` instance against the exact same shared Kafka
    // topic/OpenSearch index — see `AuditIndexerModule`'s doc comment) a
    // moment to finish delivering these 12 events' worth of already-queued
    // messages, then deliberately empty this tenant's slice of the index —
    // the real "the index was lost/corrupted" scenario Section 45 asks to
    // prove recoverable. Deleting is retried to convergence rather than
    // once: a concurrently-running indexer processing the *same* 12
    // messages independently can still land a write moments after this
    // test's own delete call returns — bounded retries let this test's own
    // delete reliably "win" the race without asserting on a fundamentally
    // racy single delete call.
    let emptied = false;
    for (let attempt = 0; attempt < 10 && !emptied; attempt += 1) {
      await openSearchIndexService.dangerouslyDeleteAllForTenantForTests(
        tenant.id,
      );
      await new Promise((resolve) => setTimeout(resolve, 300));
      emptied = (await openSearchIndexService.count(tenant.id)) === 0;
    }
    expect(await openSearchIndexService.count(tenant.id)).toBe(0);

    const { count } = await auditReindexService.reindexTenant(
      tenantClient,
      tenant.id,
    );
    expect(count).toBe(12);

    expect(await openSearchIndexService.count(tenant.id)).toBe(12);
    for (const eventId of recorded) {
      const doc = await openSearchIndexService.getById(eventId);
      expect(doc).not.toBeNull();
      expect(doc?.tenantId).toBe(tenant.id);
      expect(doc?.eventType).toBe(AUDIT_EVENT_TYPES.TASK_CREATED);
    }

    // Reindexing again (e.g. a retried DR run) stays idempotent — same
    // count, not double.
    await auditReindexService.reindexTenant(tenantClient, tenant.id);
    expect(await openSearchIndexService.count(tenant.id)).toBe(12);
  }, 60_000);

  it('the real AuditIndexerService never double-indexes a redelivered eventId', async () => {
    const tenant = await manager.provisionTenant({
      slug: uniqueSlug('idem'),
      name: 'OpenSearch Idempotency Test Tenant',
    });
    if (!tenant.databaseBinding) throw new Error('expected database binding');
    provisioned.push({
      tenantId: tenant.id,
      databaseName: tenant.databaseBinding.databaseName,
    });

    const redisPubSubService = new RedisPubSubService(fakeConfigService());
    await redisPubSubService.onModuleInit();
    const indexer = new AuditIndexerService(
      fakeConfigService(),
      openSearchIndexService,
      redisPubSubService,
    );
    await indexer.onModuleInit();
    // `consumer.run()` (inside `onModuleInit`) registers the message
    // callback and returns immediately — it does not wait for the
    // consumer group's rebalance/partition-assignment to actually finish.
    // A short grace period here (mirroring the live-SSE e2e suite's own
    // warm-up wait) avoids a race between "subscribed" and "actually
    // ready to receive," the same reasoning `test/audit-live-sse.e2e-spec.ts`
    // documents for its own SSE connections.
    await new Promise((resolve) => setTimeout(resolve, 2_000));

    try {
      const brokers = (process.env.KAFKA_BROKERS ?? 'localhost:29092')
        .split(',')
        .map((b) => b.trim());
      const kafka = new KafkaJS.Kafka({
        kafkaJS: { brokers, clientId: 'audit-opensearch-indexing-producer' },
      });
      const producer = kafka.producer();
      await producer.connect();

      const eventId = randomUUID();
      const envelope = {
        eventId,
        eventType: AUDIT_EVENT_TYPES.TASK_CREATED,
        eventVersion: 1,
        tenantId: tenant.id,
        timestamp: new Date().toISOString(),
        correlationId: randomUUID(),
        actor: { type: 'system' as const, id: 'idempotency-test' },
        data: { marker: 'first-delivery' },
        previousHash: null,
        eventHash: 'a'.repeat(64),
        sequence: 1,
      };
      const redelivered = { ...envelope, data: { marker: 'redelivered' } };

      await producer.send({
        topic: AUDIT_EVENTS_TOPIC,
        messages: [{ key: tenant.id, value: JSON.stringify(envelope) }],
      });
      await producer.send({
        topic: AUDIT_EVENTS_TOPIC,
        messages: [{ key: tenant.id, value: JSON.stringify(redelivered) }],
      });
      await producer.disconnect();

      // Bounded wait for the real consumer to process both messages.
      let doc: Awaited<ReturnType<typeof openSearchIndexService.getById>> =
        null;
      const deadline = Date.now() + 20_000;
      while (Date.now() < deadline) {
        doc = await openSearchIndexService.getById(eventId);
        if (
          doc?.data &&
          (doc.data as { marker?: string }).marker === 'redelivered'
        ) {
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 500));
      }

      expect(doc).not.toBeNull();
      expect((doc?.data as { marker?: string })?.marker).toBe('redelivered');
      expect(await openSearchIndexService.count(tenant.id)).toBe(1);
    } finally {
      await indexer.onModuleDestroy();
      await redisPubSubService.onModuleDestroy();
    }
  }, 30_000);
});
