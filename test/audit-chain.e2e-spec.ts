import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import { AppConfig } from '../src/config/env.validation';
import { ControlPrismaService } from '../src/database/control-prisma.service';
import { EnvSecretProvider } from '../src/database/env-secret-provider';
import { TenantDatabaseManager } from '../src/database/tenant-database-manager.service';
import { AuditService } from '../src/audit/audit.service';
import { KafkaPublisherService } from '../src/audit/kafka-publisher.service';
import { AUDIT_EVENT_TYPES } from '../src/audit/audit-event-types';

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
    KAFKA_CLIENT_ID: 'audit-chain-e2e-test',
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
    ...overrides,
  };
  return {
    get: (key: keyof AppConfig) => values[key],
  } as unknown as ConfigService<AppConfig, true>;
}

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
    // Exactly one event has previousHash === null (the very first one ever
    // recorded for this tenant) — a second null would itself be a fork
    // (two "first" events).
    expect(events.filter((e) => e.previousHash === null)).toHaveLength(1);
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
});
