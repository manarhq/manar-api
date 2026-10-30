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
  ownerSubject: string;
  kind: WorkspaceKind;
  displayName: string;
  /** COMPANY: the Entra tenant the workspace belongs to. */
  entraTenantId?: string;
  /** Display hints for the owner's Membership; never used for access decisions. */
  ownerEmail?: string;
  ownerDisplayName?: string;
}

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

    let tenantId: string;
    let status: 'ACTIVE' | 'QUEUED';
    try {
      const tenant = await this.manager.provisionTenant({
        slug,
        name,
        kind: input.kind,
        ownerSubject: input.kind === 'COMPANY' ? undefined : input.ownerSubject,
        entraTenantId:
          input.kind === 'COMPANY' ? input.entraTenantId : undefined,
        queued,
      });
      tenantId = tenant.id;
      status = tenant.status === 'ACTIVE' ? 'ACTIVE' : 'QUEUED';
    } catch (error) {
      if (error instanceof TenantSlugConflictError) {
        // The slug is random, so a conflict is the one-per-owner / one-per-Entra-tenant index.
        if (input.kind !== 'COMPANY') {
          const existing = await this.control.tenant.findFirst({
            where: { kind: input.kind, ownerSubject: input.ownerSubject },
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
        // Rows exist but the database leg failed: keep the owner attached so ops can retry.
        await this.attachOwner(slug, input);
      }
      throw error;
    }

    await this.attachOwner(slug, input, tenantId);
    return { tenantId, status };
  }

  private async attachOwner(
    slug: string,
    input: CreateWorkspaceInput,
    knownTenantId?: string,
  ): Promise<void> {
    const tenantId =
      knownTenantId ??
      (await this.control.tenant.findUnique({ where: { slug } }))?.id;
    if (!tenantId) return;
    const roles = ownerRoles();
    await this.control.membership.upsert({
      where: { subject_tenantId: { subject: input.ownerSubject, tenantId } },
      create: {
        subject: input.ownerSubject,
        tenantId,
        role: roles.role,
        extraRoles: roles.extraRoles,
        status: 'ACTIVE',
        email: input.ownerEmail,
        displayName: input.ownerDisplayName,
        grantedBy: 'system:workspace-create',
      },
      update: {},
    });
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
    if (tenant.status === 'PROVISIONING') {
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
      this.control.tenant.count({ where: { status: 'PROVISIONING' } }),
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
      const inflight = await this.control.tenant.count({
        where: { status: 'PROVISIONING' },
      });
      const slots =
        authSetting(this.config, 'WORKSPACE_PROVISION_CONCURRENCY') - inflight;
      if (slots <= 0) return 0;
      const queued = await this.control.tenant.findMany({
        where: { status: 'QUEUED' },
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
  constructor(private readonly control: ControlPrismaService) {}

  async find(ownerSubject: string): Promise<string | null> {
    const tenant = await this.control.tenant.findFirst({
      where: {
        kind: 'SAMPLE',
        ownerSubject,
        status: { not: 'DELETED' },
        memberships: { some: { subject: ownerSubject, status: 'ACTIVE' } },
      },
      select: { id: true },
    });
    return tenant?.id ?? null;
  }
}
