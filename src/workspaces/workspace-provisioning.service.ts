import { randomBytes } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { authSetting } from '../auth/auth.config';
import { ownerRoles, type WorkspaceKind } from '../auth/membership.service';
import type { AppConfig } from '../config/env.validation';
import { ControlPrismaService } from '../database/control-prisma.service';
import {
  TenantProvisioningError,
  TenantSlugConflictError,
} from '../database/tenant-database.errors';
import type { SampleDirectory, WorkspaceProvisioning } from './workspace-ports';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';

export interface CreateWorkspaceInput {
  /** Issuer of `ownerSubject`. Absent: the deployment's primary issuer (first of AUTH_ISSUERS). */
  ownerIssuer?: string;
  ownerSubject: string;
  kind: WorkspaceKind;
  displayName: string;
  /** COMPANY: the Entra tenant the workspace belongs to. */
  entraTenantId?: string;
  /** Display hints for the owner's Membership; never used for access decisions. */
  ownerEmail?: string;
  ownerDisplayName?: string;
}

/** A PROVISIONING attempt not touched for this long has lost its worker. */
const STALL_MS = 10 * 60_000;
const staleBefore = (): Date => new Date(Date.now() - STALL_MS);

export interface CreateWorkspaceResult {
  tenantId: string;
  status: 'ACTIVE' | 'QUEUED';
}

const SLUG_PREFIX: Record<WorkspaceKind, string> = {
  PERSONAL: 'p',
  COMPANY: 'c',
  SAMPLE: 's',
};

/**
 * Hosted workspace creation (spec 4.2): a tenant database plus the owner's Membership. There is
 * no per-tenant Keycloak realm (users sign in to the shared realm). Wraps
 * `TenantDatabaseManager.provisionTenant`.
 *
 * Capacity: when provisioning is busy or the database count is near its limit, the tenant is
 * recorded QUEUED and a drain loop provisions it in order. Nobody is refused; the owner
 * Membership exists from the start so "Setting up your workspace" can follow it.
 */
@Injectable()
export class WorkspaceProvisioningService implements WorkspaceProvisioning {
  private readonly logger = new Logger(WorkspaceProvisioningService.name);
  private draining = false;
  private lastWarnAt = 0;

  constructor(
    private readonly manager: TenantDatabaseManager,
    private readonly control: ControlPrismaService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async createWorkspace(
    input: CreateWorkspaceInput,
  ): Promise<CreateWorkspaceResult> {
    const queued = await this.shouldQueue();
    const slug = `${SLUG_PREFIX[input.kind]}-${randomBytes(8).toString('hex')}`;
    const name = input.displayName.trim().slice(0, 120) || 'Workspace';

    const issuer = this.issuerFor(input.ownerIssuer);
    const roles = ownerRoles();

    try {
      const tenant = await this.manager.provisionTenant({
        slug,
        name,
        kind: input.kind,
        ownerSubject: input.kind === 'COMPANY' ? undefined : input.ownerSubject,
        ownerIssuer: input.kind === 'COMPANY' ? undefined : issuer,
        entraTenantId:
          input.kind === 'COMPANY' ? input.entraTenantId : undefined,
        queued,
        retryOnFailure: true,
        // Same transaction as the tenant rows: no tenant without its owner.
        owner: {
          issuer,
          subject: input.ownerSubject,
          role: 'TENANT_OWNER',
          extraRoles: roles.extraRoles.filter((r) => r !== 'TENANT_OWNER'),
          email: input.ownerEmail,
          displayName: input.ownerDisplayName,
        },
      });
      return {
        tenantId: tenant.id,
        status: tenant.status === 'ACTIVE' ? 'ACTIVE' : 'QUEUED',
      };
    } catch (error) {
      if (error instanceof TenantSlugConflictError) {
        // The slug is random, so a conflict is the one-per-owner / one-per-Entra-tenant index.
        if (input.kind !== 'COMPANY') {
          const existing = await this.control.tenant.findFirst({
            where: {
              kind: input.kind,
              ownerIssuer: issuer,
              ownerSubject: input.ownerSubject,
            },
          });
          if (existing) {
            return {
              tenantId: existing.id,
              status: existing.status === 'ACTIVE' ? 'ACTIVE' : 'QUEUED',
            };
          }
        }
        throw new ConflictException('workspace_exists');
      }
      if (error instanceof TenantProvisioningError) {
        // The rows and the owner exist and the tenant is back in the queue: the user sees
        // "Setting up your workspace" and the drain loop retries with a back-off.
        this.logger.warn(`Workspace ${slug} will be retried from the queue`);
        const row = await this.control.tenant.findUnique({ where: { slug } });
        if (row) return { tenantId: row.id, status: 'QUEUED' };
      }
      throw error;
    }
  }

  private issuerFor(explicit?: string): string {
    const issuer =
      explicit?.replace(/\/+$/, '') ??
      (this.config.get('AUTH_ISSUERS', { infer: true }) ?? '')
        .split(',')
        .map((i) => i.trim().replace(/\/+$/, ''))
        .find(Boolean);
    if (!issuer) throw new ForbiddenException('issuer_required');
    return issuer;
  }

  /**
   * Removes a SAMPLE workspace for good: marks it DELETED (every guard refuses it from then on),
   * drops its database, then deletes its rows (memberships and the catalog cascade). Anything that
   * is not a SAMPLE, or is still being provisioned, is refused.
   */
  async deleteWorkspace(tenantId: string): Promise<void> {
    const tenant = await this.control.tenant.findUnique({
      where: { id: tenantId },
      include: { databaseBinding: true },
    });
    if (!tenant) return;
    if (tenant.kind !== 'SAMPLE') {
      throw new ForbiddenException('only_sample_workspaces_can_be_deleted');
    }
    if (tenant.status === 'PROVISIONING' && tenant.updatedAt > staleBefore()) {
      throw new ConflictException('workspace_busy');
    }
    if (tenant.databaseBinding) {
      if (tenant.status !== 'DELETED') {
        await this.manager.deprovisionTenant(tenantId);
      }
      if (tenant.status !== 'QUEUED') {
        await this.manager.dangerouslyDropTenantDatabase(tenantId);
      }
    }
    await this.control.$transaction([
      this.control.auditSealMark.deleteMany({ where: { tenantId } }),
      this.control.secretReference.deleteMany({ where: { tenantId } }),
      this.control.tenantDatabaseBinding.deleteMany({ where: { tenantId } }),
      this.control.tenant.delete({ where: { id: tenantId } }),
    ]);
  }

  /** True when a new sign-up must wait: a backlog exists, provisioning is saturated, or the database count is near its limit. */
  async shouldQueue(): Promise<boolean> {
    const [total, inflight, backlog] = await Promise.all([
      this.control.tenant.count({
        where: { status: { in: ['ACTIVE', 'PROVISIONING', 'QUEUED'] } },
      }),
      this.control.tenant.count({
        where: { status: 'PROVISIONING', updatedAt: { gt: staleBefore() } },
      }),
      this.control.tenant.count({ where: { status: 'QUEUED' } }),
    ]);
    const max = authSetting(this.config, 'WORKSPACE_MAX_TENANTS');
    const ratio = total / max;
    if (ratio >= 0.7 && Date.now() - this.lastWarnAt > 60_000) {
      this.lastWarnAt = Date.now();
      // The alert to Mohamed at 70% of headroom keys on this line (capacity=workspaces).
      this.logger.warn(
        `capacity=workspaces used=${total} max=${max} ratio=${ratio.toFixed(2)} queued=${backlog} provisioning=${inflight}`,
      );
    }
    return (
      backlog > 0 ||
      inflight >= authSetting(this.config, 'WORKSPACE_PROVISION_CONCURRENCY') ||
      ratio >= authSetting(this.config, 'WORKSPACE_QUEUE_AT_RATIO')
    );
  }

  /** A PROVISIONING tenant nobody has touched for STALL_MS lost its worker (crash, deploy): retry it. */
  private async requeueStalled(): Promise<void> {
    const stalled = await this.control.tenant.findMany({
      where: {
        status: 'PROVISIONING',
        updatedAt: { lt: staleBefore() },
        // Hosted tenants only: personal/sample have an owner issuer, hosted company workspaces an
        // Entra tenant id. A legacy `tenant:create` tenant has neither and is left PROVISIONING for
        // a person to inspect, as before.
        OR: [{ ownerIssuer: { not: null } }, { entraTenantId: { not: null } }],
      },
      select: { id: true },
      take: 50,
    });
    for (const { id } of stalled) await this.manager.scheduleProvisionRetry(id);
  }

  /** Puts FAILED workspaces (all, or one) back in the queue with a fresh attempt count. */
  async retryFailed(tenantId?: string): Promise<number> {
    const r = await this.control.tenant.updateMany({
      where: { status: 'FAILED', ...(tenantId ? { id: tenantId } : {}) },
      data: { status: 'QUEUED', provisionAttempts: 0, nextProvisionAt: null },
    });
    return r.count;
  }

  /**
   * Provisions queued workspaces, oldest first, up to the free provisioning slots. Safe on every
   * replica at once: `provisionQueued` claims each tenant with a compare-and-set. Returns how many
   * it provisioned.
   */
  async drainQueue(): Promise<number> {
    if (this.draining) return 0;
    this.draining = true;
    let done = 0;
    try {
      await this.requeueStalled();
      // In flight = actually being worked on: a stalled or crashed attempt must not hold a slot.
      const inflight = await this.control.tenant.count({
        where: { status: 'PROVISIONING', updatedAt: { gt: staleBefore() } },
      });
      const slots =
        authSetting(this.config, 'WORKSPACE_PROVISION_CONCURRENCY') - inflight;
      if (slots <= 0) return 0;
      const queued = await this.control.tenant.findMany({
        where: {
          status: 'QUEUED',
          OR: [
            { nextProvisionAt: null },
            { nextProvisionAt: { lte: new Date() } },
          ],
        },
        orderBy: { createdAt: 'asc' },
        take: slots,
        select: { id: true },
      });
      await Promise.all(
        queued.map(async ({ id }) => {
          try {
            if (await this.manager.provisionQueued(id)) done++;
          } catch (error) {
            this.logger.error(
              `Queued workspace ${id} failed to provision: ${error instanceof Error ? error.message : String(error)}`,
            );
          }
        }),
      );
    } catch (error) {
      this.logger.error(
        `Queue drain failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      this.draining = false;
    }
    return done;
  }
}

/** Drains the queue on a timer in the HTTP app only (the CLI uses `workspaces:drain`). */
@Injectable()
export class WorkspaceQueueLoop implements OnModuleInit, OnModuleDestroy {
  private timer?: ReturnType<typeof setInterval>;

  constructor(
    private readonly provisioning: WorkspaceProvisioningService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  onModuleInit(): void {
    const every = authSetting(this.config, 'WORKSPACE_QUEUE_DRAIN_MS');
    if (every > 0) {
      this.timer = setInterval(
        () => void this.provisioning.drainQueue(),
        every,
      );
      this.timer.unref?.();
    }
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}

/** Lookup of the SAMPLE workspace a user owns. Only the owner's own ACTIVE Membership counts. */
@Injectable()
export class SampleDirectoryService implements SampleDirectory {
  constructor(
    private readonly control: ControlPrismaService,
    private readonly config: ConfigService<AppConfig, true>,
  ) {}

  async find(
    ownerSubject: string,
    ownerIssuer?: string,
  ): Promise<string | null> {
    const issuer =
      ownerIssuer?.replace(/\/+$/, '') ??
      (this.config.get('AUTH_ISSUERS', { infer: true }) ?? '')
        .split(',')
        .map((i) => i.trim().replace(/\/+$/, ''))
        .find(Boolean);
    if (!issuer) return null;
    const tenant = await this.control.tenant.findFirst({
      where: {
        kind: 'SAMPLE',
        ownerIssuer: issuer,
        ownerSubject,
        status: { not: 'DELETED' },
        memberships: {
          some: { issuer, subject: ownerSubject, status: 'ACTIVE' },
        },
      },
      select: { id: true },
    });
    return tenant?.id ?? null;
  }
}
