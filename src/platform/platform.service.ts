import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  TenantLifecycleConflictError,
  TenantProvisioningError,
  TenantSlugConflictError,
} from '../database/tenant-database.errors';
import { TenantProvisioningService } from '../keycloak/tenant-provisioning.service';
import { PlatformSuspension } from './platform-suspension';
import type { CreatePlatformTenant } from './platform.validation';

const USAGE_WINDOW_DAYS = 30;
const ADMIN_ROLES = ['TENANT_OWNER', 'SECURITY_ADMIN'] as const;

type ControlTenant = {
  id: string;
  slug: string;
  name: string;
  status: string;
  residency: string;
  createdAt: Date;
};

const view = (t: ControlTenant) => ({
  id: t.id,
  slug: t.slug,
  name: t.name,
  status: t.status,
  residency: t.residency,
  createdAt: t.createdAt,
});

/**
 * Tenant lifecycle for manar-fleet (ADR-0010). Reads and writes control-plane rows and, for the
 * summary, counts in the tenant database. Never returns tenant business data: admin contacts,
 * tool names and counts only.
 */
@Injectable()
export class PlatformService {
  private readonly logger = new Logger(PlatformService.name);

  constructor(
    private readonly control: ControlPrismaService,
    private readonly tenants: TenantDatabaseManager,
    private readonly provisioning: TenantProvisioningService,
    private readonly suspension: PlatformSuspension,
  ) {}

  async list() {
    const rows = await this.control.tenant.findMany({
      orderBy: { createdAt: 'asc' },
    });
    return rows.map(view);
  }

  async create(input: CreatePlatformTenant, caller: string) {
    try {
      const t = await this.provisioning.provisionTenant(input);
      this.logger.log(`platform: tenant ${t.id} provisioned by ${caller}`);
      return view(t);
    } catch (error) {
      if (error instanceof TenantSlugConflictError)
        throw new ConflictException('A tenant with this slug already exists');
      if (error instanceof TenantProvisioningError)
        throw new InternalServerErrorException('Tenant provisioning failed');
      throw error;
    }
  }

  private async tenantOr404(id: string) {
    const t = await this.control.tenant.findUnique({ where: { id } });
    if (!t) throw new NotFoundException('No such tenant');
    return t;
  }

  /** Control fields always; admins, tools, agents and usage only while the tenant is ACTIVE. */
  async summary(id: string) {
    const t = await this.tenantOr404(id);
    if (t.status !== 'ACTIVE') return view(t);
    const db = await this.tenants.getClient(id);
    const since = new Date(Date.now() - USAGE_WINDOW_DAYS * 86_400_000);
    const [
      admins,
      tools,
      total,
      active,
      tasks,
      toolInvocations,
      approvalRequests,
    ] = await Promise.all([
      db.userProfile.findMany({
        where: { roleBindings: { some: { role: { in: [...ADMIN_ROLES] } } } },
        select: {
          displayName: true,
          email: true,
          roleBindings: { select: { role: true } },
        },
        orderBy: { displayName: 'asc' },
        take: 50,
      }),
      db.tool.findMany({
        select: { name: true, vendor: true, enabled: true },
        orderBy: { name: 'asc' },
      }),
      db.agent.count(),
      db.agent.count({ where: { status: 'ACTIVE' } }),
      db.task.count({ where: { createdAt: { gte: since } } }),
      db.toolInvocation.count({ where: { createdAt: { gte: since } } }),
      db.approvalRequest.count({ where: { createdAt: { gte: since } } }),
    ]);
    return {
      ...view(t),
      admins: admins.map((a) => ({
        displayName: a.displayName,
        email: a.email,
        roles: a.roleBindings.map((b) => b.role),
      })),
      tools,
      agents: { total, active },
      usage: {
        windowDays: USAGE_WINDOW_DAYS,
        tasks,
        toolInvocations,
        approvalRequests,
      },
    };
  }

  /**
   * Kill switch first, then the control status: every process denies on the decision path at
   * once, and humans are refused as soon as the status flips. Residual window: work already past
   * its kill-switch check when the switch lands (one in-flight request or activity).
   */
  async suspend(id: string, caller: string) {
    const t = await this.tenantOr404(id);
    if (t.status !== 'ACTIVE')
      throw new ConflictException(`Tenant is not ACTIVE`);
    await this.suspension.engage(await this.tenants.getClient(id), id, caller);
    await this.lifecycle(() => this.tenants.suspendTenant(id));
    this.logger.log(`platform: tenant ${id} suspended by ${caller}`);
    return view(await this.tenantOr404(id));
  }

  /** Control status first, then release only the platform's own kill switch. */
  async resume(id: string, caller: string) {
    await this.tenantOr404(id);
    await this.lifecycle(() => this.tenants.resumeTenant(id));
    const released = await this.suspension.release(
      await this.tenants.getClient(id),
      id,
      caller,
    );
    this.logger.log(
      `platform: tenant ${id} resumed by ${caller} (platform kill switch ${released ? 'released' : 'was not active'})`,
    );
    return view(await this.tenantOr404(id));
  }

  /** Marks the tenant DELETED after setting its kill switch. The database and realm are kept. */
  async remove(id: string, caller: string) {
    const t = await this.tenantOr404(id);
    if (t.status === 'DELETED') return view(t);
    if (t.status === 'PROVISIONING')
      throw new ConflictException('Tenant is still provisioning');
    if (t.status === 'ACTIVE')
      await this.suspension.engage(
        await this.tenants.getClient(id),
        id,
        caller,
      );
    await this.tenants.deprovisionTenant(id);
    this.logger.log(`platform: tenant ${id} deleted by ${caller}`);
    return view(await this.tenantOr404(id));
  }

  private async lifecycle(fn: () => Promise<void>) {
    try {
      await fn();
    } catch (error) {
      if (error instanceof TenantLifecycleConflictError)
        throw new ConflictException(error.message);
      throw error;
    }
  }
}
