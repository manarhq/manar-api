import {
  ConflictException,
  ForbiddenException,
  HttpException,
  Injectable,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { PushService } from '../push/push.service';
import { TelegramService } from '../telegram/telegram.service';
import { approvalMatchCode } from '../phone/phone-token';
import { createAllowGrant } from './allow-grants';
import { buildRuleDraft } from './rule-draft';

export type HostDecision = 'approve_once' | 'approve_8h' | 'deny';

/** How long a device approval waits for a person. */
export const HOST_APPROVAL_TTL_MS = 10 * 60 * 1000;

/** A host that opens more approvals than this in the window is refused (a looping tool, or a flood). */
export const HOST_APPROVALS_PER_WINDOW = 20;
export const HOST_APPROVAL_WINDOW_MS = 10 * 60 * 1000;

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
  /** push and telegram are the phone: like the device, they never give a standing 8-hour permission. */
  via: 'device' | 'console' | 'push' | 'telegram';
  makeRule?: boolean;
  /**
   * Single-use push token nonce: recorded in the same transaction as the decision, so a token is
   * spent only by a decision that took effect, and never twice.
   */
  nonce?: { value: string; expiresAt: Date };
}

@Injectable()
export class HostApprovalsService {
  constructor(
    private readonly audit: AuditService,
    private readonly push: PushService,
    @Optional() private readonly telegram?: TelegramService,
  ) {}

  /** Called by the host authorize path when the answer is "ask". Pushes to the workspace's approvers. */
  async open(
    client: TenantPrismaClient,
    tenantId: string,
    input: OpenHostApprovalInput,
    now: Date = new Date(),
  ) {
    // The same host asking again for the same thing while it is still pending is the same
    // question: reuse it (no second prompt, no second push, no second audit event).
    const existing = await client.hostApproval.findFirst({
      where: {
        hostId: input.hostId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        status: 'PENDING',
        expiresAt: { gt: now },
      },
    });
    if (existing) return existing;
    const recent = await client.hostApproval.count({
      where: {
        hostId: input.hostId,
        createdAt: { gt: new Date(now.getTime() - HOST_APPROVAL_WINDOW_MS) },
      },
    });
    if (recent >= HOST_APPROVALS_PER_WINDOW)
      throw new HttpException('too many approvals opened by this device', 429);
    // The id is made here so the short match code (shown on the device prompt, the push and
    // Telegram) can be part of the stored summary.
    const id = randomUUID();
    const matchCode = approvalMatchCode(id);
    const row = await client.hostApproval.create({
      data: {
        id,
        hostId: input.hostId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        summary: `${input.summary.slice(0, 280)} #${matchCode}`,
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
      // Tool, action type and match code. Never the resource.
      body: `${input.toolName}: ${input.actionId} #${matchCode}`,
      url: '/approvals',
      // One tag per approval: two requests never replace each other on the phone.
      tag: `approval-${row.id}`,
      approvalId: row.id,
      // High-risk approvals are decided in the console only: no buttons on the phone.
      actionable: !input.highRisk,
      expiresAt: row.expiresAt.getTime(),
    });
    void this.telegram?.notifyApproval(client, tenantId, {
      approvalId: row.id,
      toolName: input.toolName,
      actionId: input.actionId,
      matchCode,
      highRisk: input.highRisk,
      expiresAt: row.expiresAt,
    });
    return row;
  }

  /**
   * The secrets vault asks "may this program use this secret?". It is always a console decision
   * (high risk), so a WARDEN prompt on the device only points at the console.
   */
  openSecretUse(
    client: TenantPrismaClient,
    tenantId: string,
    input: { hostId: string; program: string; secretName: string },
  ) {
    return this.open(client, tenantId, {
      hostId: input.hostId,
      toolId: 'host.vault',
      actionId: 'secret.use',
      resource: input.secretName.slice(0, 512),
      summary: `${input.program.slice(0, 80)} wants to use a secret`,
      highRisk: true,
      toolName: input.program.slice(0, 40),
    });
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
    // 8 hours is a standing permission: it is given in the console, in a browser session, never
    // from a prompt on the device (a process on the device could answer that prompt).
    if (input.via !== 'console' && input.decision === 'approve_8h')
      throw new ForbiddenException('eight_hours_in_console');
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
      if (input.nonce) {
        try {
          await tx.phoneActionUse.create({
            data: {
              nonce: input.nonce.value,
              expiresAt: input.nonce.expiresAt,
            },
          });
        } catch {
          // Unique violation: the token was spent. This aborts the transaction, so the decision
          // above is rolled back with it.
          throw new ConflictException('action_already_used');
        }
      }
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
    // Close the phone's buttons and notification, whichever channel decided.
    void this.telegram?.closeApproval(
      tenantId,
      row.id,
      input.decision === 'deny' ? 'deny' : input.decision,
    );
    void this.push.notifyApprovers(client, tenantId, {
      kind: 'approval_closed',
      title: 'WARDEN',
      body: '',
      url: '/approvals',
      tag: `approval-closed-${row.id}`,
      approvalId: row.id,
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
