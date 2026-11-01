import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { PushService } from '../push/push.service';
import { SITE_CONNECT_ACTION } from '../jail/jail-sites';
import {
  siteRuleBlocksRemember,
  upsertSiteRule,
} from '../jail/jail-sites.service';
import { ALLOW_GRANT_TTL_MS, createAllowGrant } from './allow-grants';
import { buildRuleDraft } from './rule-draft';

/** `approve_always` exists for a new site only (JAIL): it makes a permanent site rule. */
export type HostDecision =
  'approve_once' | 'approve_8h' | 'approve_always' | 'deny';

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
  via: 'device' | 'console';
  makeRule?: boolean;
  /** Console only: the caller may write site rules (owner / security admin). Absent means no. */
  canWriteSiteRules?: boolean;
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
      // One tag per device: a burst of requests collapses into one notification.
      tag: `approval-host-${input.hostId}`,
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
    if (
      input.via === 'device' &&
      (input.decision === 'approve_8h' || input.decision === 'approve_always')
    )
      throw new ForbiddenException('eight_hours_in_console');
    const row = await this.get(client, input.approvalId, input.hostId);
    const isSite = row.actionId === SITE_CONNECT_ACTION;
    if (input.decision === 'approve_always' && !isSite)
      throw new BadRequestException('always is for a new site only');
    // A permanent site rule needs the role that may write site rules; an approver without it
    // gets "once" (fail closed: an absent flag is "no").
    let decision: HostDecision = input.decision;
    let note: 'always_needs_owner' | 'site_rule_exists' | null = null;
    if (decision === 'approve_always' && !input.canWriteSiteRules) {
      decision = 'approve_once';
      note = 'always_needs_owner';
    }
    const wantsRemember =
      isSite && (decision === 'approve_8h' || decision === 'approve_always');
    let remember = false;
    const result = await client.$transaction(async (tx) => {
      // A person's answer to "may this tool connect to this site?" is remembered per device and
      // tool, unless a DENY or a rule made by hand already speaks for this site: then it is
      // "once", and the stored decision says so (the device reads it).
      if (
        wantsRemember &&
        (await siteRuleBlocksRemember(
          tx,
          row.hostId,
          row.toolId,
          row.resource,
          now,
        ))
      ) {
        decision = 'approve_once';
        note = 'site_rule_exists';
      }
      const won = await tx.hostApproval.updateMany({
        where: { id: row.id, status: 'PENDING', expiresAt: { gt: now } },
        data: {
          status: decision === 'deny' ? 'DENIED' : 'APPROVED',
          decision,
          decidedBy: input.subject,
          decidedVia: input.via,
          decidedAt: now,
        },
      });
      if (won.count === 0)
        throw new ConflictException('already decided or expired');
      if (wantsRemember && note !== 'site_rule_exists') {
        await upsertSiteRule(tx, {
          hostId: row.hostId,
          toolId: row.toolId,
          site: row.resource,
          mode: 'ALLOW',
          expiresAt:
            decision === 'approve_always'
              ? null
              : new Date(now.getTime() + ALLOW_GRANT_TTL_MS),
          source: 'approval',
          createdBy: input.subject,
        });
        remember = true;
      }
      // A site prompt is answered by the site rule, never by an 8-hour action grant.
      if (decision !== 'approve_8h' || isSite)
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
        decision === 'deny'
          ? AUDIT_EVENT_TYPES.APPROVAL_DENIED
          : AUDIT_EVENT_TYPES.APPROVAL_APPROVED,
      actor: { type: 'human', id: input.subject },
      data: {
        hostApprovalId: row.id,
        hostId: row.hostId,
        decision,
        via: input.via,
        toolId: row.toolId,
        actionId: row.actionId,
      },
    });
    if (remember) {
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.JAIL_SITE_RULE_CREATED,
        actor: { type: 'human', id: input.subject },
        data: {
          hostId: row.hostId,
          toolId: row.toolId,
          site: row.resource,
          mode: 'ALLOW',
          via: input.via,
          decision,
        },
      });
    }
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
      status: decision === 'deny' ? ('DENIED' as const) : ('APPROVED' as const),
      decision,
      grantId: result.grantId,
      /** True when a site rule was made; `note` says why not ("once" only). */
      remembered: remember,
      note,
      ruleDraft:
        input.makeRule && decision !== 'deny'
          ? buildRuleDraft({
              toolId: row.toolId,
              actionId: row.actionId,
              resource: row.resource,
            })
          : null,
    };
  }
}
