import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from './control-prisma.service';
import { EnvSecretProvider } from './env-secret-provider';
import { TenantDatabaseManager } from './tenant-database-manager.service';
import {
  TenantCreatorLimitError,
  TenantNotFoundError,
  TenantSlugConflictError,
} from './tenant-database.errors';
import { EnforcementDependencyUnavailableException } from '../common/fail-closed/fail-closed';

/**
 * Mandatory tenant-isolation invariant tests (design spec's "Testing
 * strategy" section, Section 80 of the master prompt). These run against
 * the real local Postgres started by `pnpm infra:up` — never mocked, since
 * a mocked database can't catch a real cross-tenant leak. Each test
 * provisions real databases via `TenantDatabaseManager.provisionTenant`,
 * which spawns a real `prisma migrate deploy` child process.
 *
 * Requires `CONTROL_DATABASE_URL` to point at a running Postgres (see .env /
 * .env.example and deploy/docker-compose.yml). `TENANT_DB_BASE_URL` defaults
 * to the same server's `postgres` database, as in .env.example and CI.
 */

if (!process.env.CONTROL_DATABASE_URL) {
  throw new Error(
    'tenant-database-manager.spec needs CONTROL_DATABASE_URL (a running Postgres, see .env.example)',
  );
}
if (!process.env.TENANT_DB_BASE_URL) {
  const base = new URL(process.env.CONTROL_DATABASE_URL);
  base.pathname = '/postgres';
  process.env.TENANT_DB_BASE_URL = base.toString();
}

function fakeConfigService(
  overrides: Partial<AppConfig> = {},
): ConfigService<AppConfig, true> {
  const values: AppConfig = {
    PORT: 3000,
    METRICS_PORT: 0,
    WORKER_METRICS_PORT: 0,
    MANAR_DEPLOYMENT: 'customer',
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
    FLEET_AUDIT_VERIFY_MINUTES: 60,
    FLEET_HEARTBEAT_KEY_PATH: 'fleet/heartbeat-signing-key',
    APPROVAL_GRANT_TTL_MS: 300_000,
    APPROVAL_REQUEST_TTL_MS: 1_800_000,
    APPROVAL_DECIDE_RESULT_TIMEOUT_MS: 120_000,
    KAFKA_BROKERS: process.env.KAFKA_BROKERS ?? 'localhost:29092',
    KAFKA_CLIENT_ID: process.env.KAFKA_CLIENT_ID ?? 'manar-api',
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
    LLM_DEFAULT_UAE_RESIDENT: 'false',
    MANAR_EDGE_ENABLED: 'false',
    MANAR_EDGE_CIDR: '100.88.0.0/16',
    LLM_OLLAMA_BASE_URL: 'http://localhost:11434/v1',
    LLM_MODEL: 'qwen3.5:9b',
    LLM_AZURE_OPENAI_API_VERSION: '2024-10-21',
    LLM_TASK_TOKEN_BUDGET: 200_000,
    LLM_UPSTREAM_TIMEOUT_MS: 180_000,
    LLM_ANTHROPIC_PROVIDER: 'none',
    LLM_ANTHROPIC_BASE_URL: 'https://api.anthropic.com',
    LLM_ANTHROPIC_MODELS: '',
    LLM_ANTHROPIC_UAE_RESIDENT: 'false',
    LLM_ANTHROPIC_BETAS: '',
    LLM_STREAM_MAX_MS: 900_000,
    LLM_ANTHROPIC_STREAM_DLP: 'buffer',
    ...overrides,
  };
  return {
    get: (key: keyof AppConfig) => values[key],
  } as unknown as ConfigService<AppConfig, true>;
}

function uniqueSlug(label: string): string {
  return `iso-${label}-${randomUUID().slice(0, 8)}`;
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

describe('TenantDatabaseManager (tenant isolation invariants)', () => {
  let control: ControlPrismaService;
  let manager: TenantDatabaseManager;

  const provisioned: { tenantId: string; databaseName: string }[] = [];

  let tenantA: Awaited<ReturnType<TenantDatabaseManager['provisionTenant']>>;
  let tenantB: Awaited<ReturnType<TenantDatabaseManager['provisionTenant']>>;

  beforeAll(async () => {
    control = new ControlPrismaService(fakeConfigService());
    await control.$connect();
    manager = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );

    tenantA = await manager.provisionTenant({
      slug: uniqueSlug('a'),
      name: 'Isolation Tenant A',
    });
    tenantB = await manager.provisionTenant({
      slug: uniqueSlug('b'),
      name: 'Isolation Tenant B',
    });

    if (!tenantA.databaseBinding || !tenantB.databaseBinding) {
      throw new Error(
        'Expected provisioned tenants to have a database binding',
      );
    }
    provisioned.push(
      {
        tenantId: tenantA.id,
        databaseName: tenantA.databaseBinding.databaseName,
      },
      {
        tenantId: tenantB.id,
        databaseName: tenantB.databaseBinding.databaseName,
      },
    );
  }, 60_000);

  afterAll(async () => {
    await manager.onModuleDestroy();
    for (const { tenantId, databaseName } of provisioned) {
      await cleanupTenant(control, tenantId, databaseName);
    }
    await control.$disconnect();
  }, 60_000);

  it('1. provisions two tenants with distinct databaseNames and distinct SecretReferences', async () => {
    expect(tenantA.databaseBinding?.databaseName).toBeTruthy();
    expect(tenantB.databaseBinding?.databaseName).toBeTruthy();
    expect(tenantA.databaseBinding?.databaseName).not.toBe(
      tenantB.databaseBinding?.databaseName,
    );

    const secretRefA = await control.secretReference.findUniqueOrThrow({
      where: { id: tenantA.databaseBinding!.secretReferenceId },
    });
    const secretRefB = await control.secretReference.findUniqueOrThrow({
      where: { id: tenantB.databaseBinding!.secretReferenceId },
    });
    expect(secretRefA.id).not.toBe(secretRefB.id);
  }, 20_000);

  it('2. each tenant client resolves SELECT current_database() to its own database, never the other', async () => {
    const clientA = await manager.getClient(tenantA.id);
    const clientB = await manager.getClient(tenantB.id);

    const [rowA] = await clientA.$queryRaw<{ current_database: string }[]>`
      SELECT current_database()
    `;
    const [rowB] = await clientB.$queryRaw<{ current_database: string }[]>`
      SELECT current_database()
    `;

    expect(rowA?.current_database).toBe(tenantA.databaseBinding?.databaseName);
    expect(rowB?.current_database).toBe(tenantB.databaseBinding?.databaseName);
    expect(rowA?.current_database).not.toBe(rowB?.current_database);
  }, 20_000);

  it('3. never returns the same live client instance for two different tenants, and the bounded LRU cache evicts under load', async () => {
    const clientA = await manager.getClient(tenantA.id);
    const clientB = await manager.getClient(tenantB.id);
    expect(clientA).not.toBe(clientB);

    // Small dedicated manager (max=2) sharing the same control connection,
    // exercised against tenants A/B plus a third tenant provisioned just
    // for this scenario, to keep the LRU test fast and independent of the
    // shared-fixture cache state above.
    const smallManager = new TenantDatabaseManager(
      control,
      fakeConfigService({ TENANT_DB_CLIENT_CACHE_MAX: 2 }),
      new EnvSecretProvider(),
    );
    const tenantC = await manager.provisionTenant({
      slug: uniqueSlug('c'),
      name: 'Isolation Tenant C',
    });
    provisioned.push({
      tenantId: tenantC.id,
      databaseName: tenantC.databaseBinding!.databaseName,
    });

    try {
      const firstA = await smallManager.getClient(tenantA.id);
      await smallManager.getClient(tenantB.id);
      // Cache is now at its max (2). Fetching a third distinct tenant must
      // evict the least-recently-used entry (tenantA) rather than growing
      // unbounded.
      await smallManager.getClient(tenantC.id);
      expect(
        (smallManager as unknown as { cache: Map<string, unknown> }).cache.size,
      ).toBeLessThanOrEqual(2);

      // Re-fetching tenantA must produce a *new* client instance, proving
      // the earlier one was evicted (and disconnected) rather than reused.
      const secondA = await smallManager.getClient(tenantA.id);
      expect(secondA).not.toBe(firstA);
    } finally {
      await smallManager.onModuleDestroy();
    }
  }, 60_000);

  it('4. resolving an unknown or deprovisioned tenant ID fails closed', async () => {
    await expect(manager.getClient(randomUUID())).rejects.toThrow();
    await expect(manager.resolveTenant(randomUUID())).rejects.toThrow();

    await manager.deprovisionTenant(tenantB.id);
    await expect(manager.getClient(tenantB.id)).rejects.toThrow();
  }, 20_000);

  it('6. a client cached in one process stops serving a tenant suspended by another process once the revalidation TTL passes', async () => {
    // Two managers = two processes (e.g. API replica and Temporal worker), sharing the control DB.
    const worker = new TenantDatabaseManager(
      control,
      fakeConfigService({ TENANT_DB_CLIENT_REVALIDATE_MS: 50 }),
      new EnvSecretProvider(),
    );
    const api = new TenantDatabaseManager(
      control,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    try {
      await worker.getClient(tenantA.id); // cached in the "worker"
      await api.suspendTenant(tenantA.id); // evicts only in the "api" process
      await new Promise((r) => setTimeout(r, 80));
      await expect(worker.getClient(tenantA.id)).rejects.toBeInstanceOf(
        TenantNotFoundError,
      );
      expect(
        (worker as unknown as { cache: Map<string, unknown> }).cache.has(
          tenantA.id,
        ),
      ).toBe(false);
    } finally {
      await api.resumeTenant(tenantA.id);
      await worker.onModuleDestroy();
      await api.onModuleDestroy();
    }
  }, 30_000);

  it('7. if the control DB cannot be read on revalidation, the cached client is never returned', async () => {
    let down = false;
    const flakyControl = {
      tenant: {
        findUnique: (args: Parameters<typeof control.tenant.findUnique>[0]) =>
          down
            ? Promise.reject(new Error('connection refused'))
            : control.tenant.findUnique(args),
      },
    } as unknown as ControlPrismaService;
    const m = new TenantDatabaseManager(
      flakyControl,
      fakeConfigService({ TENANT_DB_CLIENT_REVALIDATE_MS: 0 }),
      new EnvSecretProvider(),
    );
    try {
      await m.getClient(tenantA.id);
      down = true;
      await expect(m.getClient(tenantA.id)).rejects.toBeInstanceOf(
        EnforcementDependencyUnavailableException,
      );
    } finally {
      await m.onModuleDestroy();
    }
  }, 30_000);

  it('8. a suspend that lands while a new client is connecting is caught before the client is cached', async () => {
    let reads = 0;
    const racyControl = {
      tenant: {
        findUnique: async (
          args: Parameters<typeof control.tenant.findUnique>[0],
        ) => {
          reads++;
          const real = await control.tenant.findUnique(args);
          // First read (resolve) sees ACTIVE; the post-connect re-check sees the suspend.
          return reads === 1 || !real ? real : { ...real, status: 'SUSPENDED' };
        },
      },
    } as unknown as ControlPrismaService;
    const m = new TenantDatabaseManager(
      racyControl,
      fakeConfigService(),
      new EnvSecretProvider(),
    );
    try {
      await expect(m.getClient(tenantA.id)).rejects.toBeInstanceOf(
        TenantNotFoundError,
      );
      expect((m as unknown as { cache: Map<string, unknown> }).cache.size).toBe(
        0,
      );
    } finally {
      await m.onModuleDestroy();
    }
  }, 30_000);

  it('5. re-provisioning an existing slug fails with a clear conflict error, not a duplicate database', async () => {
    const before = await control.$queryRaw<{ count: bigint }[]>`
      SELECT count(*)::bigint AS count FROM pg_database WHERE datname = ${tenantA.databaseBinding!.databaseName}
    `;
    expect(before[0]?.count).toBe(1n);

    await expect(
      manager.provisionTenant({
        slug: tenantA.slug,
        name: 'Duplicate Attempt',
      }),
    ).rejects.toThrow(TenantSlugConflictError);

    const after = await control.$queryRaw<{ count: bigint }[]>`
      SELECT count(*)::bigint AS count FROM pg_database WHERE datname = ${tenantA.databaseBinding!.databaseName}
    `;
    expect(after[0]?.count).toBe(1n);

    const tenantCount = await control.tenant.count({
      where: { slug: tenantA.slug },
    });
    expect(tenantCount).toBe(1);
  }, 30_000);

  it('10. AI defaults on, except Government and air-gapped; an explicit value is kept and recorded as chosen', async () => {
    const mk = (extra: object) =>
      manager.provisionTenant({
        slug: uniqueSlug('ai'),
        name: 'AI default',
        queued: true,
        ...extra,
      });
    const made = {
      personal: await mk({
        kind: 'PERSONAL',
        ownerSubject: 'p',
        ownerIssuer: 'i',
      }),
      company: await mk({ kind: 'COMPANY' }),
      legacyCli: await mk({}),
      government: await mk({ kind: 'COMPANY', sector: 'GOVERNMENT' }),
      commercial: await mk({ kind: 'COMPANY', sector: 'COMMERCIAL' }),
      airGapped: await mk({ residency: 'AIR_GAPPED' }),
      explicitOff: await mk({ allowExternalAi: false }),
    };
    try {
      expect(made.personal.allowExternalAi).toBe(true);
      expect(made.company.allowExternalAi).toBe(true);
      expect(made.legacyCli.allowExternalAi).toBe(true);
      expect(made.government.allowExternalAi).toBe(false);
      // Government is an explicit, recorded decision; the sector is stored.
      expect(made.government.allowExternalAiChosen).toBe(true);
      expect(made.government.sector).toBe('GOVERNMENT');
      expect(made.commercial.sector).toBe('COMMERCIAL');
      expect(made.commercial.allowExternalAi).toBe(true);
      expect(made.company.sector).toBeNull();
      expect(made.airGapped.allowExternalAi).toBe(false);
      expect(made.explicitOff.allowExternalAi).toBe(false);
      expect(made.company.allowExternalAiChosen).toBe(false);
      expect(made.explicitOff.allowExternalAiChosen).toBe(true);
    } finally {
      await control.tenant.deleteMany({
        where: { id: { in: Object.values(made).map((t) => t.id) } },
      });
    }
  });

  it('9. the per-creator cap holds under parallel requests and counts tenants whatever happened to them since', async () => {
    const subject = `creator-${randomUUID()}`;
    const creator = {
      issuer: 'https://auth.test/realms/manar',
      subject,
      maxOfKind: 3,
    };
    // Queued: only the control-DB rows are written, which is where the cap is decided.
    const attempts = await Promise.allSettled(
      Array.from({ length: 8 }, (_, i) =>
        manager.provisionTenant({
          slug: uniqueSlug(`cap${i}`),
          name: 'Cap',
          kind: 'COMPANY',
          queued: true,
          creator,
        }),
      ),
    );
    const made = attempts.filter((a) => a.status === 'fulfilled');
    expect(made).toHaveLength(3);
    for (const a of attempts) {
      if (a.status === 'rejected') {
        expect(a.reason).toBeInstanceOf(TenantCreatorLimitError);
      }
    }

    // A tenant marked DELETED, or handed to someone else, still counts.
    const ids = made.map(
      (a) => (a as PromiseFulfilledResult<{ id: string }>).value.id,
    );
    await control.tenant.update({
      where: { id: ids[0]! },
      data: { status: 'DELETED' },
    });
    await control.membership.deleteMany({ where: { tenantId: ids[1]! } });
    await expect(
      manager.provisionTenant({
        slug: uniqueSlug('cap-late'),
        name: 'Cap',
        kind: 'COMPANY',
        queued: true,
        creator,
      }),
    ).rejects.toThrow(TenantCreatorLimitError);

    // Another person is unaffected.
    const other = await manager.provisionTenant({
      slug: uniqueSlug('cap-other'),
      name: 'Cap',
      kind: 'COMPANY',
      queued: true,
      creator: { ...creator, subject: `${subject}-other` },
    });
    await control.$transaction([
      control.tenantDatabaseBinding.deleteMany({
        where: { tenantId: { in: [...ids, other.id] } },
      }),
      control.secretReference.deleteMany({
        where: { tenantId: { in: [...ids, other.id] } },
      }),
      control.membership.deleteMany({
        where: { tenantId: { in: [...ids, other.id] } },
      }),
      control.tenant.deleteMany({ where: { id: { in: [...ids, other.id] } } }),
    ]);
  }, 60_000);
});
