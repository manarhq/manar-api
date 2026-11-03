import {
  ForbiddenException,
  Inject,
  Injectable,
  Optional,
  forwardRef,
} from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { RoleName } from '../auth/roles';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { EdgePeerService } from '../edge/edge-peer.service';
import { isWorkspacePaused } from './pause-state';

export interface PauseStatus {
  paused: boolean;
  pausedAt: string | null;
  pausedBy: string | null;
  /** The role that paused: resuming needs a role at least as high. */
  pausedByRole: PauseRole | null;
}

/** Who can pause or resume, lowest first. */
export const PAUSE_ROLES = [
  'APPROVER',
  'SECURITY_ADMIN',
  'TENANT_OWNER',
] as const;
export type PauseRole = (typeof PAUSE_ROLES)[number];

/** The highest pause-capable role among `roles`, or null when there is none. */
export function highestPauseRole(roles: readonly RoleName[]): PauseRole | null {
  let best = -1;
  for (const r of roles)
    best = Math.max(best, PAUSE_ROLES.indexOf(r as PauseRole));
  return best < 0 ? null : (PAUSE_ROLES[best] ?? null);
}

/** A resume needs a role at least as high as the one that paused (founder rule for Company workspaces). */
export function mayResume(
  roles: readonly RoleName[],
  pausedByRole: string | null,
): boolean {
  const mine = highestPauseRole(roles);
  if (!mine) return false;
  const needed = PAUSE_ROLES.indexOf(pausedByRole as PauseRole);
  // A pause recorded without a role (never written by this code) needs the top role.
  return (
    PAUSE_ROLES.indexOf(mine) >= (needed < 0 ? PAUSE_ROLES.length - 1 : needed)
  );
}

/** "Pause all AI": one switch per workspace, read by every authorize path (kill-switch check) and by devices. */
@Injectable()
export class PauseService {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
    // forwardRef: edge-peer.service imports the kill-switch services (an import cycle), as in KillSwitchService.
    @Optional()
    @Inject(forwardRef(() => EdgePeerService))
    private readonly edgePeers?: EdgePeerService,
  ) {}

  async get(tenantId: string): Promise<PauseStatus> {
    const client = await this.tenants.getClient(tenantId);
    const row = await client.workspacePause.findUnique({
      where: { id: 'workspace' },
    });
    const on = row?.paused === true;
    return {
      paused: on,
      pausedAt: on ? (row.pausedAt?.toISOString() ?? null) : null,
      pausedBy: on ? row.pausedBy : null,
      pausedByRole: on
        ? ((row.pausedByRole as PauseRole | null) ?? null)
        : null,
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
    roles: readonly RoleName[],
    via: 'console' | 'phone' = 'console',
  ): Promise<PauseStatus> {
    const role = highestPauseRole(roles);
    if (!role) throw new ForbiddenException('role_cannot_pause');
    const client = await this.tenants.getClient(tenantId);
    const current = await this.get(tenantId);
    if (current.paused && !paused && !mayResume(roles, current.pausedByRole)) {
      throw new ForbiddenException('resume_needs_the_role_that_paused');
    }
    const now = new Date();
    const data = {
      paused,
      pausedBy: paused ? subject : null,
      pausedByRole: paused ? role : null,
      pausedAt: paused ? now : null,
    };
    // Pausing again keeps who paused first (a lower role must not take over a higher role's pause).
    const keep = paused && current.paused;
    await client.workspacePause.upsert({
      where: { id: 'workspace' },
      create: { id: 'workspace', ...data },
      update: keep ? {} : data,
    });
    let expired = 0;
    if (paused && !current.paused) {
      expired = await this.expirePending(client, tenantId);
    }
    // Only a change is an event worth a record; pressing the button twice is not.
    if (current.paused !== paused) {
      await this.audit.recordSafely(client, tenantId, {
        eventType: paused
          ? AUDIT_EVENT_TYPES.WORKSPACE_AI_PAUSED
          : AUDIT_EVENT_TYPES.WORKSPACE_AI_RESUMED,
        actor: { type: 'human', id: subject },
        data: { via, role, expiredApprovals: expired },
      });
    }
    // Edge peers recompute their cut-off state now, as for a tenant kill switch.
    await this.edgePeers?.tenantChanged(tenantId);
    return this.get(tenantId);
  }

  /**
   * Pausing denies everything still waiting for a person: no approval may be granted during a
   * pause, and what was pending is not left to be approved after it. Each gets `approval.expired`
   * with reason `paused`.
   */
  private async expirePending(
    client: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    tenantId: string,
  ): Promise<number> {
    let n = 0;
    const host = await client.hostApproval.findMany({
      where: { status: 'PENDING' },
      select: { id: true, hostId: true, toolId: true, actionId: true },
      take: 500,
    });
    for (const row of host) {
      const won = await client.hostApproval.updateMany({
        where: { id: row.id, status: 'PENDING' },
        data: { status: 'EXPIRED', endReason: 'paused' },
      });
      if (won.count === 0) continue;
      n++;
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_EXPIRED,
        actor: { type: 'system', id: row.hostId },
        data: {
          hostApprovalId: row.id,
          hostId: row.hostId,
          toolId: row.toolId,
          actionId: row.actionId,
          reason: 'paused',
        },
      });
    }
    const agent = await client.approvalRequest.findMany({
      where: { status: 'PENDING' },
      select: { id: true, agentId: true, toolId: true, actionId: true },
      take: 500,
    });
    for (const row of agent) {
      const won = await client.approvalRequest.updateMany({
        where: { id: row.id, status: 'PENDING' },
        data: { status: 'EXPIRED', endReason: 'paused' },
      });
      if (won.count === 0) continue;
      n++;
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_EXPIRED,
        actor: { type: 'system', id: row.agentId },
        data: {
          approvalRequestId: row.id,
          agentId: row.agentId,
          toolId: row.toolId,
          actionId: row.actionId,
          reason: 'paused',
        },
      });
    }
    return n;
  }
}
