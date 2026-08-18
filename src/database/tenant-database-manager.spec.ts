import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { Client as PgClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from './control-prisma.service';
import { EnvSecretProvider } from './env-secret-provider';
import { TenantDatabaseManager } from './tenant-database-manager.service';
import { TenantSlugConflictError } from './tenant-database.errors';

/**
 * Mandatory tenant-isolation invariant tests (design spec's "Testing
 * strategy" section, Section 80 of the master prompt). These run against
 * the real local Postgres started by `pnpm infra:up` — never mocked, since
 * a mocked database can't catch a real cross-tenant leak. Each test
 * provisions real databases via `TenantDatabaseManager.provisionTenant`,
 * which spawns a real `prisma migrate deploy` child process.
 *
 * Requires `CONTROL_DATABASE_URL` / `TENANT_DB_BASE_URL` to point at a
 * running Postgres (see .env / .env.example and deploy/docker-compose.yml).
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
    APPROVAL_GRANT_TTL_MS: 300_000,
    APPROVAL_REQUEST_TTL_MS: 1_800_000,
    KAFKA_BROKERS: process.env.KAFKA_BROKERS ?? 'localhost:29092',
    KAFKA_CLIENT_ID: process.env.KAFKA_CLIENT_ID ?? 'manar-api',
    KAFKA_AUDIT_TOPIC: process.env.KAFKA_AUDIT_TOPIC ?? 'manar.audit-events',
    OPENSEARCH_NODE: process.env.OPENSEARCH_NODE ?? 'http://localhost:9200',
    OPENSEARCH_AUDIT_INDEX:
      process.env.OPENSEARCH_AUDIT_INDEX ?? 'manar-audit-events',
    REDIS_URL: process.env.REDIS_URL ?? 'redis://localhost:6379',
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
});
