import { Injectable } from '@nestjs/common';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';

export interface Usage {
  devices: number;
  agents: number;
  cloudAgents: number;
}

/** Reads what a tenant uses today (plan page). */
@Injectable()
export class BillableUsageService {
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
}
