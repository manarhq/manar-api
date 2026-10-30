import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { PushService } from '../push/push.service';
import { createAllowGrant } from './allow-grants';
import { buildRuleDraft } from './rule-draft';

export type HostDecision = 'approve_once' | 'approve_8h' | 'deny';

/** How long a device approval waits for a person. */
export const HOST_APPROVAL_TTL_MS = 10 * 60 * 1000;

export interface OpenHostApprovalInput {
  hostId: string;
  toolId: string;
  actionId: string;
  resource: string;
  /** One line for the prompt, built by the caller. No file contents, no prompts. */
  summary: string;
  highRisk: boolean;
  /** Shown in the push, e.g. "Cursor". */
  toolName: string;
}

export interface DecideHostApprovalInput {
  approvalId: string;
  /** Set for a decision from a device: the approval must belong to that host. */
  hostId?: string;
  subject: string;
  decision: HostDecision;
  via: 'device' | 'console';
  makeRule?: boolean;
}

@Injectable()
export class HostApprovalsService {
  constructor(
    private readonly audit: AuditService,
    private readonly push: PushService,
  ) {}

  /** Called by the host authorize path when the answer is "ask". Pushes to the workspace's approvers. */
  async open(
    client: TenantPrismaClient,
    tenantId: string,
    input: OpenHostApprovalInput,
    now: Date = new Date(),
  ) {
    const row = await client.hostApproval.create({
      data: {
        hostId: input.hostId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        summary: input.summary.slice(0, 300),
        highRisk: input.highRisk,
        expiresAt: new Date(now.getTime() + HOST_APPROVAL_TTL_MS),
      },
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_REQUESTED,
      actor: { type: 'system', id: input.hostId },
      data: {
        hostApprovalId: row.id,
        toolId: input.toolId,
        actionId: input.actionId,
        highRisk: input.highRisk,
      },
    });
    void this.push.notifyApprovers(client, tenantId, {
      kind: 'approval',
      title: 'WARDEN',
      body: `${input.toolName} is waiting for your decision`,
      url: '/approvals',
      tag: `approval-${row.id}`,
    });
    return row;
  }

  listPending(
    client: TenantPrismaClient,
    hostId: string | undefined,
    now: Date = new Date(),
  ) {
    return client.hostApproval.findMany({
      where: {
        ...(hostId ? { hostId } : {}),
        status: 'PENDING',
        expiresAt: { gt: now },
      },
      orderBy: { createdAt: 'asc' },
      take: 50,
    });
  }

  async get(client: TenantPrismaClient, id: string, hostId?: string) {
    const row = await client.hostApproval.findUnique({ where: { id } });
    if (!row || (hostId && row.hostId !== hostId))
      throw new NotFoundException('no such approval');
    return row;
  }

  /**
   * Records the decision once (conditional update on PENDING and not expired) and, for approve_8h,
   * creates the grant in the same transaction. The caller has already checked who may decide.
   */
  async decide(
    client: TenantPrismaClient,
    tenantId: string,
    input: DecideHostApprovalInput,
    now: Date = new Date(),
  ) {
    const row = await this.get(client, input.approvalId, input.hostId);
    const result = await client.$transaction(async (tx) => {
      const won = await tx.hostApproval.updateMany({
        where: { id: row.id, status: 'PENDING', expiresAt: { gt: now } },
        data: {
          status: input.decision === 'deny' ? 'DENIED' : 'APPROVED',
          decision: input.decision,
          decidedBy: input.subject,
          decidedVia: input.via,
          decidedAt: now,
        },
      });
      if (won.count === 0)
        throw new ConflictException('already decided or expired');
      if (input.decision !== 'approve_8h')
        return { grantId: null as string | null };
      const grant = await createAllowGrant(tx, {
        scope: { hostId: row.hostId },
        target: {
          toolId: row.toolId,
          actionId: row.actionId,
          resource: row.resource,
        },
        createdBy: input.subject,
        sourceId: row.id,
        now,
      });
      return { grantId: grant.id };
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType:
        input.decision === 'deny'
          ? AUDIT_EVENT_TYPES.APPROVAL_DENIED
          : AUDIT_EVENT_TYPES.APPROVAL_APPROVED,
      actor: { type: 'human', id: input.subject },
      data: {
        hostApprovalId: row.id,
        hostId: row.hostId,
        decision: input.decision,
        via: input.via,
        toolId: row.toolId,
        actionId: row.actionId,
      },
    });
    if (result.grantId) {
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_CREATED,
        actor: { type: 'human', id: input.subject },
        data: {
          grantId: result.grantId,
          hostId: row.hostId,
          toolId: row.toolId,
          actionId: row.actionId,
          via: input.via,
        },
      });
    }
    return {
      id: row.id,
      status:
        input.decision === 'deny' ? ('DENIED' as const) : ('APPROVED' as const),
      decision: input.decision,
      grantId: result.grantId,
      ruleDraft:
        input.makeRule && input.decision !== 'deny'
          ? buildRuleDraft({
              toolId: row.toolId,
              actionId: row.actionId,
              resource: row.resource,
            })
          : null,
    };
  }
}
