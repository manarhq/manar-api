import {
  BadRequestException,
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
import { dbNow } from '../common/db-clock';
import { PAUSED_REASON, isWorkspacePaused } from '../pause/pause-state';
import { SITE_CONNECT_ACTION } from '../jail/jail-sites';
import {
  siteRuleBlocksRemember,
  upsertSiteRule,
} from '../jail/jail-sites.service';
import { ALLOW_GRANT_TTL_MS, createAllowGrant } from './allow-grants';
import { buildRuleDraft } from './rule-draft';
import { ApproverDirectory, choicesFor } from './approver-directory';
import {
  PAUSED_CONFLICT_MESSAGE,
  approvalConflict,
  notPendingConflict,
} from './approvals.errors';

/** `approve_always` exists for a new site only (JAIL): it makes a permanent site rule. */
export type HostDecision =
  'approve_once' | 'approve_8h' | 'approve_always' | 'deny';

/**
 * How long a device approval waits for a person (founder decision, 1 Nov 2026): the prompt shows
 * and the phone is pushed at the same moment; with no answer in 2 minutes it is denied, logged,
 * and the agent is told "denied: no answer".
 */
export const HOST_APPROVAL_TTL_MS = 2 * 60 * 1000;

/** A host that opens more approvals than this in the window is refused (a looping tool, or a flood). */
export const HOST_APPROVALS_PER_WINDOW = 20;
export const HOST_APPROVAL_WINDOW_MS = 10 * 60 * 1000;

/**
 * New-site asks from protected tools (JAIL) have their own budget, so a tool that reaches for many
 * sites cannot use up the device's other prompts, and its own queue is capped.
 */
export const HOST_SITE_ASKS_PER_WINDOW = 30;
export const HOST_SITE_PENDING_PER_TOOL = 10;

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
  /** Console only: the caller may write site rules (owner / security admin). Absent means no. */
  canWriteSiteRules?: boolean;
  /**
   * Device only: the device stopped waiting (its 2 minutes ran out). Recorded as EXPIRED
   * `withdrawn`, never as a person's deny. A device `deny` of a new site is always this: WARDEN
   * never shows buttons for sites, so only JAIL's own timeout sends it (edges before 3 Nov 2026
   * do not set the flag).
   */
  withdraw?: boolean;
}

@Injectable()
export class HostApprovalsService {
  constructor(
    private readonly audit: AuditService,
    private readonly push: PushService,
    private readonly approvers: ApproverDirectory,
    @Optional() private readonly telegram?: TelegramService,
  ) {}

  /** Called by the host authorize path when the answer is "ask". Pushes to the workspace's approvers. */
  async open(
    client: TenantPrismaClient,
    tenantId: string,
    input: OpenHostApprovalInput,
    at?: Date,
  ) {
    const now = at ?? (await dbNow(client));
    // Nothing new is asked while AI is paused (the authorize path has already denied it).
    if (await isWorkspacePaused(client))
      throw new ForbiddenException(PAUSED_REASON);
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
    const isSite = input.actionId === SITE_CONNECT_ACTION;
    const recent = await client.hostApproval.count({
      where: {
        hostId: input.hostId,
        createdAt: { gt: new Date(now.getTime() - HOST_APPROVAL_WINDOW_MS) },
        actionId: isSite ? SITE_CONNECT_ACTION : { not: SITE_CONNECT_ACTION },
      },
    });
    if (
      recent >= (isSite ? HOST_SITE_ASKS_PER_WINDOW : HOST_APPROVALS_PER_WINDOW)
    )
      throw new HttpException('too many approvals opened by this device', 429);
    if (isSite) {
      const waiting = await client.hostApproval.count({
        where: {
          hostId: input.hostId,
          toolId: input.toolId,
          actionId: SITE_CONNECT_ACTION,
          status: 'PENDING',
          expiresAt: { gt: now },
        },
      });
      if (waiting >= HOST_SITE_PENDING_PER_TOOL)
        throw new HttpException(
          'too many sites are waiting for this tool',
          429,
        );
    }
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

  /**
   * Denies what nobody answered in time: PENDING rows past `expiresAt` become EXPIRED (one
   * conditional update, so concurrent readers log it once) and each gets an `approval.expired`
   * audit event. Called on every read a device or console makes, so no scheduler is needed.
   */
  async expireDue(
    client: TenantPrismaClient,
    tenantId: string,
    at?: Date,
  ): Promise<number> {
    const now = at ?? (await dbNow(client));
    const due = await client.hostApproval.findMany({
      where: { status: 'PENDING', expiresAt: { lte: now } },
      select: { id: true, hostId: true, toolId: true, actionId: true },
      take: 50,
    });
    let n = 0;
    for (const row of due) {
      const won = await client.hostApproval.updateMany({
        where: { id: row.id, status: 'PENDING' },
        data: { status: 'EXPIRED', endReason: 'no_answer' },
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
          reason: 'no_answer',
        },
      });
    }
    return n;
  }

  async listPending(
    client: TenantPrismaClient,
    hostId: string | undefined,
    at?: Date,
    /** Only devices this Keycloak subject owns (a person who is not an approver). */
    opts: { ownerSubject?: string } = {},
  ) {
    const now = at ?? (await dbNow(client));
    return client.hostApproval.findMany({
      where: {
        ...(hostId ? { hostId } : {}),
        ...(opts.ownerSubject
          ? { host: { ownerSubject: opts.ownerSubject } }
          : {}),
        status: 'PENDING',
        expiresAt: { gt: now },
      },
      include: { host: { select: { hostname: true } } },
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

  /** The device stopped waiting: EXPIRED `withdrawn`, so a late answer cannot allow anything. */
  private async withdraw(
    client: TenantPrismaClient,
    tenantId: string,
    row: { id: string; hostId: string; toolId: string; actionId: string },
  ) {
    const won = await client.hostApproval.updateMany({
      where: { id: row.id, status: 'PENDING' },
      data: { status: 'EXPIRED', endReason: 'withdrawn' },
    });
    if (won.count === 1)
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_EXPIRED,
        actor: { type: 'system', id: row.hostId },
        data: {
          hostApprovalId: row.id,
          hostId: row.hostId,
          toolId: row.toolId,
          actionId: row.actionId,
          reason: 'withdrawn',
        },
      });
    return {
      id: row.id,
      status: 'EXPIRED' as const,
      decision: null,
      grantId: null,
      remembered: false,
      note: null,
      ruleDraft: null,
    };
  }

  /**
   * The device read this approval. The first read of an APPROVED one marks it used: from then on
   * the action may have run, so a revoke can only flag it. Conditional, so it races a revoke
   * cleanly: whichever lands first decides whether the device sees APPROVED or REVOKED.
   */
  async readForDevice(client: TenantPrismaClient, id: string, hostId: string) {
    await client.hostApproval.updateMany({
      where: { id, hostId, status: 'APPROVED', usedAt: null },
      data: { usedAt: await dbNow(client) },
    });
    return this.get(client, id, hostId);
  }

  /**
   * Records the decision once (conditional update on PENDING and not expired) and, for approve_8h,
   * creates the grant in the same transaction. The caller has already checked who may decide.
   */
  async decide(
    client: TenantPrismaClient,
    tenantId: string,
    input: DecideHostApprovalInput,
    at?: Date,
  ) {
    // 8 hours is a standing permission: it is given in the console, in a browser session, never
    // from a prompt on the device (a process on the device could answer that prompt).
    if (
      input.via !== 'console' &&
      (input.decision === 'approve_8h' || input.decision === 'approve_always')
    )
      throw new ForbiddenException('eight_hours_in_console');
    const row = await this.get(client, input.approvalId, input.hostId);
    const isSite = row.actionId === SITE_CONNECT_ACTION;
    // A prompt on the desktop is not consent for a new site: a protected tool can answer it itself
    // (it can run its own copy of the prompt helper). From a device only "deny" is taken, which is
    // what withdraws a prompt nobody answered.
    if (input.via === 'device' && isSite && input.decision !== 'deny')
      throw new ForbiddenException('site_in_console');
    if (input.decision === 'approve_always' && !isSite)
      throw new BadRequestException('always is for a new site only');
    if (
      input.via === 'device' &&
      input.decision === 'deny' &&
      (input.withdraw || isSite)
    )
      return this.withdraw(client, tenantId, row);
    // Founder decision, 3 Nov 2026: an approver decides anything; the device's owner decides
    // their own device's requests unless the workspace is "admins only". Checked here, where every
    // channel (console, device, phone, Telegram) arrives, so no caller can skip it.
    const owner = await client.host.findUnique({
      where: { id: row.hostId },
      select: { ownerSubject: true },
    });
    const kind = await this.approvers.deciderKind(
      tenantId,
      client,
      input.subject,
      owner?.ownerSubject,
    );
    if (!kind)
      throw new ForbiddenException(
        'Only a workspace approver or the owner of this device can answer this request. Nothing was changed.',
      );
    if (!choicesFor(kind, row).includes(input.decision))
      throw new ForbiddenException(
        'As the owner of this device you can approve once or deny. Longer approvals need a workspace approver. Nothing was changed.',
      );
    // A permanent site rule needs the role that may write site rules; an approver without it
    // gets "once" (fail closed: an absent flag is "no").
    let decision: HostDecision = input.decision;
    let note: 'needs_owner' | 'site_rule_exists' | null = null;
    if (
      isSite &&
      (decision === 'approve_always' || decision === 'approve_8h') &&
      !input.canWriteSiteRules
    ) {
      decision = 'approve_once';
      note = 'needs_owner';
    }
    const wantsRemember =
      isSite && (decision === 'approve_8h' || decision === 'approve_always');
    let remember = false;
    const result = await client.$transaction(async (tx) => {
      // Inside the transaction, so a pause that lands between the check and the write cannot be
      // missed. A deny is always allowed; an approval is refused while AI is paused.
      if (input.decision !== 'deny' && (await isWorkspacePaused(tx)))
        throw approvalConflict('paused', PAUSED_CONFLICT_MESSAGE);
      const now = at ?? (await dbNow(tx));
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
      if (won.count === 0) {
        const current = await tx.hostApproval.findUnique({
          where: { id: row.id },
          select: { status: true },
        });
        // PENDING past its expiry is expired; the sweeper has not written it yet.
        throw notPendingConflict(
          !current || current.status === 'PENDING' ? 'EXPIRED' : current.status,
        );
      }
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
          throw approvalConflict(
            'action_already_used',
            'This button was already used. Nothing was changed.',
          );
        }
      }
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
    // Close the phone's buttons and notification, whichever channel decided.
    void this.telegram?.closeApproval(tenantId, row.id, decision);
    void this.push.notifyApprovers(client, tenantId, {
      kind: 'approval_closed',
      title: 'WARDEN',
      body: '',
      url: '/approvals',
      tag: `approval-closed-${row.id}`,
      approvalId: row.id,
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
