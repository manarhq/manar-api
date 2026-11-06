import { pgPoolOptions, poolSettings } from './pool-options';
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
import { authSetting } from '../auth/auth.config';
import { failClosed, throwFailClosed } from '../common/fail-closed/fail-closed';
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
  TenantCreatorLimitError,
  TenantSlugConflictError,
} from './tenant-database.errors';

const execFileAsync = promisify(execFile);

/**
 * AI is on by default (opt-out, disclosed in the DPA and shown in Settings) only where the
 * workspace is positively recorded as COMMERCIAL and not air-gapped. An unknown sector (staff
 * provisioning that does not say) stays off and is not a recorded choice; Government is off.
 */
export function defaultAllowExternalAi(input: {
  residency?: 'UAE' | 'CUSTOM_REGION' | 'AIR_GAPPED';
  sector?: 'COMMERCIAL' | 'GOVERNMENT';
}): boolean {
  return input.residency !== 'AIR_GAPPED' && input.sector === 'COMMERCIAL';
}

export interface ProvisionTenantInput {
  slug: string;
  name: string;
  residency?: 'UAE' | 'CUSTOM_REGION' | 'AIR_GAPPED';
  /** Absent: `defaultAllowExternalAi`. */
  allowExternalAi?: boolean;
  /** Recorded on the tenant. Government: AI off, recorded as an explicit choice. Absent: unknown. */
  sector?: 'COMMERCIAL' | 'GOVERNMENT';
  allowOutboundTelemetry?: boolean;
  allowCloudStorage?: boolean;
  /** Hosted workspaces (spec 4.1). Absent for the legacy `tenant:create` path (COMPANY). */
  kind?: 'PERSONAL' | 'COMPANY' | 'SAMPLE';
  ownerSubject?: string;
  ownerIssuer?: string;
  entraTenantId?: string;
  /** Record the tenant as QUEUED and provision it later (`provisionQueued`). */
  queued?: boolean;
  /**
   * Hosted workspaces: a failed database leg puts the tenant back in the queue with a back-off
   * (and FAILED after `MAX_PROVISION_ATTEMPTS`) instead of leaving it PROVISIONING for ever.
   */
  retryOnFailure?: boolean;
  /**
   * Who asked for the workspace, recorded on the tenant. With `maxOfKind`, at most that many
   * tenants of `kind` may ever carry this creator (deleted and transferred ones count): checked
   * and written in the same transaction under a lock on the creator, so parallel requests cannot
   * pass it together. Over it: `TenantCreatorLimitError`, nothing written.
   */
  creator?: { issuer: string; subject: string; maxOfKind?: number };
  /** Created with the tenant rows in ONE transaction, so a crash cannot leave an unreachable workspace. */
  owner?: {
    issuer: string;
    subject: string;
    role: 'TENANT_OWNER';
    extraRoles: (
      | 'SECURITY_ADMIN'
      | 'AI_GOVERNANCE_MANAGER'
      | 'SOC_OPERATOR'
      | 'APPROVER'
      | 'AUDITOR'
      | 'DEVELOPER'
      | 'READ_ONLY'
    )[];
    email?: string;
    displayName?: string;
  };
}

/** After this many failed attempts a hosted tenant is FAILED and waits for `workspaces:retry`. */
export const MAX_PROVISION_ATTEMPTS = 5;

/** Back-off before the next try: 30 s, 60 s, 2 min, ... capped at 30 min. */
export function provisionBackoffMs(attempts: number): number {
  return Math.min(30_000 * 2 ** Math.max(0, attempts - 1), 30 * 60_000);
}

export interface MigrateAllResult {
  migrated: { tenantId: string; version: string }[];
  failed: { tenantId: string; slug: string; error: string }[];
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
  /** In-flight client builds, one per tenant (single-flight). */
  private readonly building = new Map<string, Promise<TenantPrismaClient>>();
  /** Clients dropped from the cache and waiting out their in-flight queries before $disconnect. */
  private readonly retiring = new Map<
    ReturnType<typeof setTimeout>,
    TenantPrismaClient
  >();
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

    // Concurrent misses for one tenant share a single build: two builds would overwrite each
    // other in the cache and leak the loser's pool.
    const inflight = this.building.get(tenantId);
    if (inflight) return inflight;
    const build = this.buildClient(tenantId).finally(() =>
      this.building.delete(tenantId),
    );
    this.building.set(tenantId, build);
    return build;
  }

  /**
   * Runs `fn` on a client of its own with a single connection, closed afterwards. For long
   * read-only work (the evidence export) that must not hold connections of the shared tenant
   * pool the decision path uses. Fails closed for a tenant that is not ACTIVE.
   */
  async withDedicatedClient<T>(
    tenantId: string,
    fn: (client: TenantPrismaClient) => Promise<T>,
  ): Promise<T> {
    const tenant = await this.resolveTenant(tenantId).catch(
      (error: unknown) => {
        if (error instanceof TenantNotFoundError) throw error;
        return throwFailClosed('control-db', error);
      },
    );
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
    const settings = poolSettings(
      (k) => this.configService.get(k as never),
      'tenant',
    );
    const client = new TenantPrismaClient({
      adapter: new PrismaPg(
        pgPoolOptions(connectionString, { ...settings, max: 1 }),
      ),
    });
    try {
      await client.$connect();
      return await fn(client);
    } finally {
      await client.$disconnect().catch(() => undefined);
    }
  }

  private async buildClient(tenantId: string): Promise<TenantPrismaClient> {
    // The stale window starts when the status is read, not when the client is ready.
    const readAt = Date.now();
    // A control DB that cannot answer (down, or its pool exhausted past DB_POOL_CONNECT_TIMEOUT_MS)
    // is a fail-closed 503, not a bare 500; an unknown tenant stays TenantNotFoundError.
    const tenant = await this.resolveTenant(tenantId).catch(
      (error: unknown) => {
        if (error instanceof TenantNotFoundError) throw error;
        return throwFailClosed('control-db', error);
      },
    );

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
      adapter: new PrismaPg(
        pgPoolOptions(
          connectionString,
          poolSettings((k) => this.configService.get(k as never), 'tenant'),
        ),
      ),
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

    if (input.queued) {
      return this.control.tenant.findUniqueOrThrow({
        where: { id: created.tenant.id },
        include: { databaseBinding: true },
      });
    }
    return this.finishProvisioning(
      created,
      input.slug,
      baseUrl,
      input.retryOnFailure ?? false,
    );
  }

  /**
   * Puts a tenant whose database leg failed (or stalled) back in the queue with a back-off, or
   * FAILED once it has used up its attempts. Only acts on a tenant still PROVISIONING.
   */
  async scheduleProvisionRetry(tenantId: string): Promise<void> {
    const t = await this.control.tenant.findUnique({
      where: { id: tenantId },
      select: { status: true, provisionAttempts: true },
    });
    if (t?.status !== 'PROVISIONING') return;
    const attempts = t.provisionAttempts + 1;
    await this.control.tenant.updateMany({
      where: { id: tenantId, status: 'PROVISIONING' },
      data:
        attempts >= MAX_PROVISION_ATTEMPTS
          ? {
              status: 'FAILED',
              provisionAttempts: attempts,
              nextProvisionAt: null,
            }
          : {
              status: 'QUEUED',
              provisionAttempts: attempts,
              nextProvisionAt: new Date(
                Date.now() + provisionBackoffMs(attempts),
              ),
            },
    });
  }

  /**
   * Provisions a tenant that was recorded QUEUED (capacity was low at sign-up). The claim is a
   * compare-and-set on the status, so two workers never provision the same tenant. Returns null
   * if someone else took it.
   */
  async provisionQueued(tenantId: string) {
    const claimed = await this.control.tenant.updateMany({
      where: { id: tenantId, status: 'QUEUED' },
      data: { status: 'PROVISIONING' },
    });
    if (claimed.count === 0) return null;
    const tenant = await this.control.tenant.findUniqueOrThrow({
      where: { id: tenantId },
      include: { databaseBinding: true },
    });
    const binding = tenant.databaseBinding;
    if (!binding) throw new TenantNotFoundError(tenantId);
    const baseUrl = await this.secretProvider.resolve({
      provider: 'ENV',
      reference: DEFAULT_TENANT_DB_SECRET_REFERENCE,
    });
    return this.finishProvisioning(
      { tenant, binding },
      tenant.slug,
      baseUrl,
      true,
    );
  }

  private async finishProvisioning(
    created: {
      tenant: { id: string };
      binding: { id: string; databaseName: string };
    },
    slug: string,
    baseUrl: string,
    retryOnFailure: boolean,
  ) {
    const databaseName = created.binding.databaseName;
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
      if (retryOnFailure) {
        await this.scheduleProvisionRetry(created.tenant.id);
      }
      this.logger.error(
        retryOnFailure
          ? `Provisioning failed for tenant "${slug}" (tenantId=${created.tenant.id}); queued for retry`
          : `Provisioning failed for tenant "${slug}" after control-DB rows were created (tenantId=${created.tenant.id}); leaving status as PROVISIONING for manual inspection`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new TenantProvisioningError(slug, error);
    }
  }

  /**
   * Applies pending tenant migrations to every ACTIVE tenant database and records the version on
   * its binding. Run on every deploy, before the new API version takes traffic.
   *
   * Tenants run with bounded concurrency (`TENANT_MIGRATE_CONCURRENCY`) so thousands of small
   * personal workspaces finish in reasonable time without opening thousands of connections. A
   * failure does not stop the run: it is collected and reported, and the caller decides what a
   * partial result means (the CLI exits non-zero). A tenant that failed keeps its old schema
   * version and stays untouched for inspection.
   */
  async migrateAllTenants(
    concurrency = authSetting(this.configService, 'TENANT_MIGRATE_CONCURRENCY'),
  ): Promise<MigrateAllResult> {
    const tenants = await this.control.tenant.findMany({
      where: {
        status: 'ACTIVE',
        databaseBinding: { provisioningStatus: 'ACTIVE' },
      },
      include: { databaseBinding: { include: { secretReference: true } } },
      orderBy: { createdAt: 'asc' },
    });

    const result: MigrateAllResult = { migrated: [], failed: [] };
    let next = 0;
    const worker = async (): Promise<void> => {
      while (next < tenants.length) {
        const tenant = tenants[next++];
        const binding = tenant?.databaseBinding;
        if (!tenant || !binding) continue;
        try {
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
          result.migrated.push({ tenantId: tenant.id, version });
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          this.logger.error(
            `Migration failed for tenant "${tenant.slug}": ${message}`,
          );
          result.failed.push({
            tenantId: tenant.id,
            slug: tenant.slug,
            error: message,
          });
        }
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(concurrency, tenants.length) }, worker),
    );
    return result;
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
      if (oldest) this.retire(oldest.client);
    }
  }

  /**
   * A caller may still be running a query on a client the LRU just dropped, and nothing tells us
   * when it is done. Disconnecting at once would fail that query (a 500 or a false deny) and
   * Prisma would quietly rebuild an untracked pool. Every query is bounded by DB_QUERY_TIMEOUT_MS,
   * so after that plus a margin nobody can still be using it.
   */
  private retire(client: TenantPrismaClient): void {
    const wait =
      (this.configService.get('DB_QUERY_TIMEOUT_MS', { infer: true }) ??
        35_000) + 5_000;
    const t = setTimeout(() => {
      this.retiring.delete(t);
      void client.$disconnect().catch(() => undefined);
    }, wait);
    t.unref?.();
    this.retiring.set(t, client);
    // ponytail: timed, not ref-counted (callers hold clients without a release call); module
    // destroy disconnects whatever is still waiting.
  }

  private evictIdleClients(): void {
    const now = Date.now();
    for (const [tenantId, cached] of this.cache) {
      if (now - cached.lastUsedAt >= this.idleTtlMs) {
        this.cache.delete(tenantId);
        this.retire(cached.client);
      }
    }
  }

  private async disconnectAll(): Promise<void> {
    const clients = [...this.cache.values()].map((c) => c.client);
    this.cache.clear();
    for (const [t, c] of this.retiring) {
      clearTimeout(t);
      clients.push(c);
    }
    this.retiring.clear();
    await Promise.all(clients.map((c) => c.$disconnect()));
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
      const creator = input.creator;
      const kind = input.kind ?? 'COMPANY';
      if (creator?.maxOfKind !== undefined) {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`workspace-creator:${creator.issuer}\n${creator.subject}`}, 0))`;
        const made = await tx.tenant.count({
          where: {
            createdByIssuer: creator.issuer,
            createdBySubject: creator.subject,
            kind,
          },
        });
        if (made >= creator.maxOfKind) {
          throw new TenantCreatorLimitError(creator.maxOfKind);
        }
      }
      const tenant = await tx.tenant.create({
        data: {
          slug: input.slug,
          name: input.name,
          status: input.queued ? 'QUEUED' : 'PROVISIONING',
          kind,
          createdByIssuer: creator?.issuer ?? null,
          createdBySubject: creator?.subject ?? null,
          ownerSubject: input.ownerSubject ?? null,
          ownerIssuer: input.ownerIssuer ?? null,
          entraTenantId: input.entraTenantId ?? null,
          residency: input.residency ?? 'UAE',
          allowExternalAi:
            input.allowExternalAi ?? defaultAllowExternalAi(input),
          allowExternalAiChosen:
            input.allowExternalAi !== undefined ||
            input.sector === 'GOVERNMENT',
          sector: input.sector ?? null,
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

      if (input.owner) {
        await tx.membership.create({
          data: {
            issuer: input.owner.issuer,
            subject: input.owner.subject,
            tenantId: tenant.id,
            role: input.owner.role,
            extraRoles: input.owner.extraRoles,
            status: 'ACTIVE',
            email: input.owner.email,
            displayName: input.owner.displayName,
            grantedBy: 'system:workspace-create',
          },
        });
      }

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
      // A retry finds the database a previous attempt already created.
      const existing = await admin.query(
        'SELECT 1 FROM pg_database WHERE datname = $1',
        [databaseName],
      );
      if (existing.rowCount === 0) {
        await admin.query(`CREATE DATABASE "${databaseName}"`);
      }
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
