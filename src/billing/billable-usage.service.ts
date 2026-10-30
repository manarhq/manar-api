import { Injectable, Logger } from '@nestjs/common';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { computeBillable, monthStart } from './billable';

export interface Usage {
  devices: number;
  agents: number;
  cloudAgents: number;
}

/** Reads what a tenant uses today (plan page) and what it owes this month (Company job). */
@Injectable()
export class BillableUsageService {
  private readonly logger = new Logger(BillableUsageService.name);

  constructor(private readonly tenants: TenantDatabaseManager) {}

  async usage(tenantId: string): Promise<Usage> {
    const db = await this.tenants.getClient(tenantId);
    const [devices, agents, cloudAgents] = await Promise.all([
      db.host.count({ where: { status: 'APPROVED' } }),
      db.agent.count({
        where: {
          status: { in: ['PENDING_ENROLLMENT', 'ACTIVE'] },
          cloudBinding: null,
        },
      }),
      db.cloudAgentBinding.count({ where: { agent: { status: 'ACTIVE' } } }),
    ]);
    return { devices, agents, cloudAgents };
  }

  async billable(
    tenantId: string,
    now = new Date(),
  ): Promise<{ users: number; extraDevices: number }> {
    const db = await this.tenants.getClient(tenantId);
    const [owners, signedIn] = await Promise.all([
      this.deviceOwners(tenantId),
      db.userProfile.findMany({
        where: { lastSeenAt: { gte: monthStart(now) } },
        select: { keycloakSubject: true },
      }),
    ]);
    return computeBillable(
      owners,
      signedIn.map((u) => u.keycloakSubject),
    );
  }

  /** One entry per enrolled device: its owner's Keycloak subject. */
  private async deviceOwners(tenantId: string): Promise<(string | null)[]> {
    const db = await this.tenants.getClient(tenantId);
    try {
      const rows = await db.$queryRaw<
        { ownerSubject: string | null }[]
      >`SELECT "ownerSubject" FROM "hosts" WHERE "status" = 'APPROVED'`;
      return rows.map((r) => r.ownerSubject);
    } catch (error) {
      // The `devices` track adds hosts."ownerSubject"; until its migration runs, nobody owns a device.
      if (!String(error).includes('ownerSubject')) throw error;
      this.logger.warn(`hosts.ownerSubject missing for tenant "${tenantId}"`);
      return [];
    }
  }
}
