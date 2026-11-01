import { Injectable } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { isWorkspacePaused } from './pause-state';

export interface PauseStatus {
  paused: boolean;
  pausedAt: string | null;
  pausedBy: string | null;
}

/** "Pause all AI": one switch per workspace, read by every authorize path (kill-switch check) and by devices. */
@Injectable()
export class PauseService {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  async get(tenantId: string): Promise<PauseStatus> {
    const client = await this.tenants.getClient(tenantId);
    const row = await client.workspacePause.findUnique({
      where: { id: 'workspace' },
    });
    return {
      paused: row?.paused === true,
      pausedAt: row?.paused ? (row.pausedAt?.toISOString() ?? null) : null,
      pausedBy: row?.paused ? row.pausedBy : null,
    };
  }

  /** Cheap flag for `GET /host/v1/config`. Throws on a database error: the device keeps its last value. */
  async isPaused(tenantId: string): Promise<boolean> {
    return isWorkspacePaused(await this.tenants.getClient(tenantId));
  }

  async set(
    tenantId: string,
    paused: boolean,
    subject: string,
    via: 'console' | 'phone' = 'console',
  ): Promise<PauseStatus> {
    const client = await this.tenants.getClient(tenantId);
    const was = await isWorkspacePaused(client);
    const now = new Date();
    await client.workspacePause.upsert({
      where: { id: 'workspace' },
      create: {
        id: 'workspace',
        paused,
        pausedBy: paused ? subject : null,
        pausedAt: paused ? now : null,
      },
      update: {
        paused,
        pausedBy: paused ? subject : null,
        pausedAt: paused ? now : null,
      },
    });
    // Only a change is an event worth a record; pressing the button twice is not.
    if (was !== paused) {
      await this.audit.recordSafely(client, tenantId, {
        eventType: paused
          ? AUDIT_EVENT_TYPES.WORKSPACE_AI_PAUSED
          : AUDIT_EVENT_TYPES.WORKSPACE_AI_RESUMED,
        actor: { type: 'human', id: subject },
        data: { via },
      });
    }
    return this.get(tenantId);
  }
}
