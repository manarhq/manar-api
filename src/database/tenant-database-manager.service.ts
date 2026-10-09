import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Inject, Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { Client as PgClient } from 'pg';
import { Prisma as ControlPrisma } from '../generated/control-client/client';
import { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AppConfig } from '../config/env.validation';
import { failClosed } from '../common/fail-closed/fail-closed';
import { ControlPrismaService } from './control-prisma.service';
import {
  DEFAULT_TENANT_DB_SECRET_REFERENCE,
  SECRET_PROVIDER,
} from './secret-provider';
import type { SecretProvider } from './secret-provider';
import {
  TenantLifecycleConflictError,
  TenantNotFoundError,
  TenantProvisioningError,
  TenantSlugConflictError,
} from './tenant-database.errors';

const execFileAsync = promisify(execFile);

export interface ProvisionTenantInput {
  slug: string;
  name: string;
  residency?: 'UAE' | 'CUSTOM_REGION' | 'AIR_GAPPED';
  allowExternalAi?: boolean;
  allowOutboundTelemetry?: boolean;
  allowCloudStorage?: boolean;
}

interface CachedClient {
  client: TenantPrismaClient;
  lastUsedAt: number;
  /** When the tenant's status and binding were last confirmed ACTIVE in the control DB. */
  validatedAt: number;
}

/**
 * Resolves, caches, and provisions per-tenant Prisma clients. This is the
 * only place in the codebase that constructs a tenant-scoped Prisma
 * client — see docs/tenant-isolation.md for the full control/tenant DB
 * split rationale.
 */
@Injectable()
export class TenantDatabaseManager implements OnModuleDestroy {
  private readonly logger = new Logger(TenantDatabaseManager.name);

  /**
   * Bounded LRU cache of live tenant clients, keyed by tenant ID. Insertion
   * order doubles as recency order (re-inserting on access moves an entry
   * to the end) — never an unbounded per-request client (Section 10).
   */
  private readonly cache = new Map<string, CachedClient>();
  private readonly maxCacheSize: number;
  private readonly idleTtlMs: number;
  private readonly revalidateMs: number;
  private readonly idleSweepInterval: ReturnType<typeof setInterval>;

  constructor(
    private readonly control: ControlPrismaService,
    private readonly configService: ConfigService<AppConfig, true>,
    @Inject(SECRET_PROVIDER) private readonly secretProvider: SecretProvider,
  ) {
    this.maxCacheSize = configService.get('TENANT_DB_CLIENT_CACHE_MAX', {
      infer: true,
    });
    this.idleTtlMs = configService.get('TENANT_DB_CLIENT_IDLE_TTL_MS', {
      infer: true,
    });
    this.revalidateMs = configService.get('TENANT_DB_CLIENT_REVALIDATE_MS', {
      infer: true,
    });

    // Sweep at half the idle TTL (bounded to a sane range) so idle clients
    // are evicted promptly without a busy-loop for very small TTLs (tests
    // configure a small TTL deliberately, per the spec's LRU test).
    const sweepMs = Math.max(50, Math.min(this.idleTtlMs / 2, 60_000));
    this.idleSweepInterval = setInterval(() => {
      this.evictIdleClients();
    }, sweepMs);
    this.idleSweepInterval.unref?.();
  }

  async onModuleDestroy(): Promise<void> {
    clearInterval(this.idleSweepInterval);
    await this.disconnectAll();
  }

  /**
   * Loads a Tenant + its TenantDatabaseBinding from the control DB.
   * Existence-only check — does not enforce lifecycle status. Throws
   * `TenantNotFoundError` if the tenant or its binding doesn't exist.
   */
  async resolveTenant(tenantId: string) {
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
      include: { databaseBinding: { include: { secretReference: true } } },
    });

    const databaseBinding = tenant?.databaseBinding;
    if (!tenant || !databaseBinding) {
      throw new TenantNotFoundError(tenantId);
    }

    // Re-assembled as a fresh object literal (rather than returning `tenant`
    // directly) so the inferred return type carries `databaseBinding` as
    // non-nullable for every caller — Prisma's generated payload types are
    // complex enough that TypeScript's control-flow narrowing on the
    // `tenant.databaseBinding` property chain doesn't reliably survive
    // being returned from the function otherwise.
    return { ...tenant, databaseBinding };
  }

  /**
   * Returns a cached tenant-scoped Prisma client, or creates one. Fails
   * closed (throws `TenantNotFoundError`) for any tenant ID that doesn't
   * resolve to an ACTIVE tenant with an ACTIVE database binding — this
   * covers unknown IDs and deprovisioned/deleted/suspended tenants alike.
   * Never falls back to the control DB or another tenant's client.
   */
  async getClient(tenantId: string): Promise<TenantPrismaClient> {
    const cached = this.cache.get(tenantId);
    if (cached) {
      // A cached client is only as good as the status it was created under: another process
      // (an API replica, the Temporal worker) may have suspended or deleted the tenant since.
      // Re-check the control DB once the entry is older than TENANT_DB_CLIENT_REVALIDATE_MS.
      // ponytail: polling bounds the stale window to the TTL; upgrade path is a pub/sub
      // eviction (Redis or Postgres LISTEN/NOTIFY) on every lifecycle change.
      if (Date.now() - cached.validatedAt >= this.revalidateMs) {
        const readAt = Date.now();
        await this.revalidate(tenantId);
        cached.validatedAt = readAt;
      }
      // Move to the end of the Map to mark it most-recently-used.
      this.cache.delete(tenantId);
      cached.lastUsedAt = Date.now();
      this.cache.set(tenantId, cached);
      return cached.client;
    }

    // The stale window starts when the status is read, not when the client is ready.
    const readAt = Date.now();
    const tenant = await this.resolveTenant(tenantId);

    if (
      tenant.status !== 'ACTIVE' ||
      tenant.databaseBinding.provisioningStatus !== 'ACTIVE'
    ) {
      throw new TenantNotFoundError(tenantId);
    }

    const connectionString = await this.resolveTenantConnectionString(
      tenant.databaseBinding.secretReference,
      tenant.databaseBinding.databaseName,
    );

    const client = new TenantPrismaClient({
      adapter: new PrismaPg({ connectionString }),
    });
    await client.$connect();

    // A suspend can land while connecting; re-check once before the client is cached or used.
    const recheckAt = Date.now();
    try {
      await this.assertActive(tenantId);
    } catch (error) {
      await client.$disconnect();
      throw error;
    }

    this.evictOverflowIfNeeded();
    this.cache.set(tenantId, {
      client,
      lastUsedAt: Date.now(),
      validatedAt: Math.max(readAt, recheckAt),
    });

    return client;
  }

  /**
   * Creates the Tenant/TenantDatabaseBinding/SecretReference rows, issues
   * `CREATE DATABASE` against the Postgres server, and runs the tenant
   * schema's migrations against the new database. On failure after the
   * control-DB rows exist, the tenant is left in PROVISIONING status for
   * manual inspection — no automatic rollback this phase (see
   * docs/tenant-isolation.md).
   */
  async provisionTenant(input: ProvisionTenantInput) {
    const databaseName = buildDatabaseName(input.slug);
    const baseUrl = await this.secretProvider.resolve({
      provider: 'ENV',
      reference: DEFAULT_TENANT_DB_SECRET_REFERENCE,
    });

    let created: Awaited<ReturnType<typeof this.createTenantRows>>;

    try {
      created = await this.createTenantRows(input, databaseName);
    } catch (error) {
      if (isUniqueConstraintViolation(error)) {
        throw new TenantSlugConflictError(input.slug);
      }
      throw error;
    }

    try {
      await this.createTenantDatabase(databaseName);

      const tenantConnectionString = substituteDatabaseName(
        baseUrl,
        databaseName,
      );
      const lastMigrationVersion = await this.runTenantMigrations(
        tenantConnectionString,
      );

      const [tenant] = await this.control.$transaction([
        this.control.tenant.update({
          where: { id: created.tenant.id },
          data: { status: 'ACTIVE' },
        }),
        this.control.tenantDatabaseBinding.update({
          where: { id: created.binding.id },
          data: {
            provisioningStatus: 'ACTIVE',
            provisionedAt: new Date(),
            lastMigratedAt: new Date(),
            lastMigrationVersion,
          },
        }),
      ]);

      return this.control.tenant.findUniqueOrThrow({
        where: { id: tenant.id },
        include: { databaseBinding: true },
      });
    } catch (error) {
      this.logger.error(
        `Provisioning failed for tenant "${input.slug}" after control-DB rows were created (tenantId=${created.tenant.id}); leaving status as PROVISIONING for manual inspection`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new TenantProvisioningError(input.slug, error);
    }
  }

  /**
   * Applies pending tenant migrations to every ACTIVE tenant database and
   * records the version on its binding. Tenant migrations used to run only
   * at provisioning, so an existing tenant never received a schema change
   * after an upgrade (found in Phase 1: the demo tenant lacked
   * `agent_certificates.caRevokedAt` and every enrollment 500'd). Run on
   * every deploy, before the new API version takes traffic. Stops at the
   * first failure, leaving the remaining tenants untouched for inspection.
   */
  async migrateAllTenants(): Promise<{ tenantId: string; version: string }[]> {
    const tenants = await this.control.tenant.findMany({
      where: {
        status: 'ACTIVE',
        databaseBinding: { provisioningStatus: 'ACTIVE' },
      },
      include: { databaseBinding: { include: { secretReference: true } } },
      orderBy: { createdAt: 'asc' },
    });

    const migrated: { tenantId: string; version: string }[] = [];
    for (const tenant of tenants) {
      const binding = tenant.databaseBinding;
      if (!binding) continue;
      const version = await this.runTenantMigrations(
        await this.resolveTenantConnectionString(
          binding.secretReference,
          binding.databaseName,
        ),
      );
      await this.control.tenantDatabaseBinding.update({
        where: { id: binding.id },
        data: { lastMigratedAt: new Date(), lastMigrationVersion: version },
      });
      this.logger.log(`Migrated tenant "${tenant.slug}" to ${version}`);
      migrated.push({ tenantId: tenant.id, version });
    }
    return migrated;
  }

  /**
   * Suspends an ACTIVE tenant (platform API, ADR-0010): status SUSPENDED and the cached client
   * evicted. Human tokens then fail issuer resolution (`KnownIssuerRegistry` needs ACTIVE), agent
   * mTLS requests fail the tenant status check, and `getClient` refuses the tenant. Data and the
   * database binding are untouched, so `resumeTenant` restores access.
   */
  async suspendTenant(tenantId: string): Promise<void> {
    await this.setLifecycleStatus(tenantId, 'ACTIVE', 'SUSPENDED');
  }

  async resumeTenant(tenantId: string): Promise<void> {
    await this.setLifecycleStatus(tenantId, 'SUSPENDED', 'ACTIVE');
  }

  private async setLifecycleStatus(
    tenantId: string,
    from: 'ACTIVE' | 'SUSPENDED',
    to: 'ACTIVE' | 'SUSPENDED',
  ): Promise<void> {
    const result = await this.control.tenant.updateMany({
      where: { id: tenantId, status: from },
      data: { status: to },
    });
    if (result.count !== 1) {
      throw new TenantLifecycleConflictError(tenantId, from);
    }
    await this.evict(tenantId);
  }

  /**
   * Transitions a tenant to DELETED and evicts any cached client. Does
   * **not** drop the underlying database — see
   * `dangerouslyDropTenantDatabase` for the explicit, separately-invoked
   * destructive operation, consistent with this project's stance against
   * silent destructive defaults (never wired into any normal command
   * path).
   */
  async deprovisionTenant(tenantId: string): Promise<void> {
    const tenant = await this.resolveTenant(tenantId);

    await this.control.$transaction([
      this.control.tenant.update({
        where: { id: tenant.id },
        data: { status: 'DELETED' },
      }),
      this.control.tenantDatabaseBinding.update({
        where: { id: tenant.databaseBinding.id },
        data: { provisioningStatus: 'DELETED' },
      }),
    ]);

    await this.evict(tenantId);
  }

  /**
   * DESTRUCTIVE. Drops a tenant's database outright — irreversible without
   * external backups. Deliberately **not** called by `deprovisionTenant`,
   * the CLI, or any other command path in this phase; a future admin
   * tooling phase decides how (and whether) to expose this deliberately.
   * Requires the tenant to already be DELETED as a minimal safety check.
   */
  async dangerouslyDropTenantDatabase(tenantId: string): Promise<void> {
    const tenant = await this.resolveTenant(tenantId);

    if (tenant.status !== 'DELETED') {
      throw new Error(
        `Refusing to drop the database for tenant "${tenantId}": status is "${tenant.status}", expected "DELETED". Call deprovisionTenant first.`,
      );
    }

    await this.evict(tenantId);

    const admin = await this.connectAdmin();
    try {
      await admin.query(
        `DROP DATABASE IF EXISTS "${tenant.databaseBinding.databaseName}" WITH (FORCE)`,
      );
    } finally {
      await admin.end();
    }
  }

  /**
   * Lightweight per-tenant `SELECT 1`. Exposed for a future `/health/ready`
   * aggregation — deliberately not wired in yet (see design spec: no
   * tenants exist at boot, nothing to check).
   */
  async checkHealth(tenantId: string): Promise<boolean> {
    const client = await this.getClient(tenantId);
    await client.$queryRaw`SELECT 1`;
    return true;
  }

  /**
   * Fails closed: if the control DB cannot be read the cached client is not returned
   * (`enforcement_dependency_unavailable`); if the tenant is no longer ACTIVE it is evicted and
   * the caller gets `TenantNotFoundError`.
   */
  private async revalidate(tenantId: string): Promise<void> {
    try {
      await this.assertActive(tenantId);
    } catch (error) {
      if (error instanceof TenantNotFoundError) await this.evict(tenantId);
      throw error;
    }
  }

  private async assertActive(tenantId: string): Promise<void> {
    const tenant = await failClosed('control-db', () =>
      this.control.tenant.findUnique({
        where: { id: tenantId },
        select: {
          status: true,
          databaseBinding: { select: { provisioningStatus: true } },
        },
      }),
    );
    if (
      tenant?.status !== 'ACTIVE' ||
      tenant.databaseBinding?.provisioningStatus !== 'ACTIVE'
    ) {
      throw new TenantNotFoundError(tenantId);
    }
  }

  private async evict(tenantId: string): Promise<void> {
    const cached = this.cache.get(tenantId);
    if (!cached) return;
    this.cache.delete(tenantId);
    await cached.client.$disconnect();
  }

  private evictOverflowIfNeeded(): void {
    while (this.cache.size >= this.maxCacheSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey === undefined) break;
      const oldest = this.cache.get(oldestKey);
      this.cache.delete(oldestKey);
      void oldest?.client.$disconnect();
    }
  }

  private evictIdleClients(): void {
    const now = Date.now();
    for (const [tenantId, cached] of this.cache) {
      if (now - cached.lastUsedAt >= this.idleTtlMs) {
        this.cache.delete(tenantId);
        void cached.client.$disconnect();
      }
    }
  }

  private async disconnectAll(): Promise<void> {
    const clients = [...this.cache.values()];
    this.cache.clear();
    await Promise.all(clients.map((c) => c.client.$disconnect()));
  }

  private async resolveTenantConnectionString(
    secretReference: Awaited<
      ReturnType<typeof this.resolveTenant>
    >['databaseBinding']['secretReference'],
    databaseName: string,
  ): Promise<string> {
    const baseUrl = await this.secretProvider.resolve({
      provider: secretReference.provider,
      reference: secretReference.reference,
    });
    return substituteDatabaseName(baseUrl, databaseName);
  }

  private async createTenantRows(
    input: ProvisionTenantInput,
    databaseName: string,
  ) {
    return this.control.$transaction(async (tx) => {
      const tenant = await tx.tenant.create({
        data: {
          slug: input.slug,
          name: input.name,
          status: 'PROVISIONING',
          residency: input.residency ?? 'UAE',
          allowExternalAi: input.allowExternalAi ?? false,
          allowOutboundTelemetry: input.allowOutboundTelemetry ?? false,
          allowCloudStorage: input.allowCloudStorage ?? false,
        },
      });

      const secretReference = await tx.secretReference.create({
        data: {
          tenantId: tenant.id,
          kind: 'DATABASE_CREDENTIAL',
          provider: 'ENV',
          reference: DEFAULT_TENANT_DB_SECRET_REFERENCE,
        },
      });

      const binding = await tx.tenantDatabaseBinding.create({
        data: {
          tenantId: tenant.id,
          databaseName,
          secretReferenceId: secretReference.id,
          provisioningStatus: 'PROVISIONING',
        },
      });

      return { tenant, binding };
    });
  }

  private async connectAdmin(): Promise<PgClient> {
    const client = new PgClient({
      connectionString: this.configService.get('CONTROL_DATABASE_URL', {
        infer: true,
      }),
    });
    await client.connect();
    return client;
  }

  private async createTenantDatabase(databaseName: string): Promise<void> {
    const admin = await this.connectAdmin();
    try {
      // CREATE DATABASE cannot run inside a transaction block; a plain
      // single-statement query over a fresh connection runs outside one.
      await admin.query(`CREATE DATABASE "${databaseName}"`);
    } finally {
      await admin.end();
    }
  }

  private async runTenantMigrations(
    tenantConnectionString: string,
  ): Promise<string> {
    const prismaCliEntry = path.join(
      path.dirname(require.resolve('prisma/package.json')),
      'build',
      'index.js',
    );
    const schemaPath = path.resolve(process.cwd(), 'prisma/tenant.prisma');
    const configPath = path.resolve(process.cwd(), 'prisma/tenant.config.ts');

    await execFileAsync(
      process.execPath,
      [
        prismaCliEntry,
        'migrate',
        'deploy',
        '--schema',
        schemaPath,
        '--config',
        configPath,
      ],
      {
        cwd: process.cwd(),
        env: { ...process.env, DATABASE_URL: tenantConnectionString },
      },
    );

    return latestMigrationVersion();
  }
}

function isUniqueConstraintViolation(
  error: unknown,
): error is ControlPrisma.PrismaClientKnownRequestError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { code?: unknown }).code === 'P2002'
  );
}

/**
 * Derives a valid, deterministic Postgres identifier from a tenant slug.
 * Postgres identifiers are limited to 63 bytes; the `tenant_` prefix plus a
 * truncated slug comfortably fits typical slugs while staying readable in
 * `\l` / server logs.
 */
export function buildDatabaseName(slug: string): string {
  const sanitized = slug
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '_')
    .slice(0, 55);
  return `tenant_${sanitized}`;
}

/** Replaces the path (database name) component of a Postgres connection URL. */
export function substituteDatabaseName(
  baseUrl: string,
  databaseName: string,
): string {
  const url = new URL(baseUrl);
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function latestMigrationVersion(): string {
  const migrationsDir = path.resolve(process.cwd(), 'prisma/tenant/migrations');
  const entries = fs
    .readdirSync(migrationsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const last = entries.at(-1);
  if (!last) {
    throw new Error(`No tenant migrations found in ${migrationsDir}`);
  }
  return last;
}
