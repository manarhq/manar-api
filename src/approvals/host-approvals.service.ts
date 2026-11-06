import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  UnauthorizedException,
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
import {
  ALLOW_GRANT_TTL_MS,
  ALWAYS_GRANT_TTL_MS,
  createAllowGrant,
} from './allow-grants';
import { scopeFor, scopeMatches } from './rule-scope';
import { buildRuleDraft } from './rule-draft';
import { ApproverDirectory } from './approver-directory';
import {
  STEP_UP_MAX_AGE_SECONDS,
  decisionRights,
  refusalMessage,
  sensitiveReason,
} from './decision-rights';
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
  /** Which ask this is (`ceiling` or a policy rule): a grant made from it answers only that ask. */
  askKey?: string;
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
  /** Console only: take the offered "always allow this here" (decision 37). */
  alwaysAllowHere?: boolean;
  /**
   * Console only: the signed-in person currently holds a role that may operate devices
   * (`OPERATOR_ROLES`). The owner path needs it, so a demoted owner cannot decide.
   */
  ownerMayOperate?: boolean;
  /**
   * Console only: the signed-in person's `auth_time` is within `STEP_UP_MAX_AGE_SECONDS`. Needed
   * for a personal workspace's owner approving their own sensitive request.
   */
  freshSignIn?: boolean;
}

/** The 3rd identical approval in this window earns the offer (decision 37). */
export const OFFER_AFTER_APPROVALS = 3;
export const OFFER_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

export interface RuleOffer {
  /** Narrow prefix scope the rule would cover (a folder, a web origin, or one MCP tool). */
  scope: string;
  approvals: number;
  /** How long accepting lasts, in days. */
  lastsDays: number;
  /** The ask it would answer; never sent to a client. */
  askKey: string;
}

/** What a client may see of an offer: never the internal ask key. */
export function publicOffer(
  o: RuleOffer | undefined,
): { scope: string; approvals: number; lastsDays: number } | null {
  return o
    ? { scope: o.scope, approvals: o.approvals, lastsDays: o.lastsDays }
    : null;
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
        askKey: input.askKey ?? null,
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
   * "Always allow this here" for each pending request that has earned it: the same device, tool,
   * action and normalised scope approved by a person 3 times in 30 days. Never for high-risk,
   * secret or handover requests, a new site, or a scope that is too broad; offered once.
   */
  async offersFor(
    client: TenantPrismaClient,
    rows: Array<{
      id: string;
      hostId: string;
      toolId: string;
      actionId: string;
      resource: string;
      highRisk: boolean;
      askKey?: string | null;
    }>,
    at?: Date,
  ): Promise<Map<string, RuleOffer>> {
    const out = new Map<string, RuleOffer>();
    const now = at ?? new Date();
    // Cheap checks first, then three queries for the whole page instead of three per row.
    const cands: Array<{
      r: (typeof rows)[number];
      scope: string;
      askKey: string;
    }> = [];
    for (const r of rows) {
      if (r.highRisk || r.actionId === SITE_CONNECT_ACTION) continue;
      // An offer answers one ask; a request without one (older) is never offered.
      if (!r.askKey || sensitiveReason(r)) continue;
      const scope = scopeFor(r.toolId, r.actionId, r.resource);
      if (scope) cands.push({ r, scope, askKey: r.askKey });
    }
    if (cands.length === 0) return out;
    const hostIds = [...new Set(cands.map((c) => c.r.hostId))];
    const toolIds = [...new Set(cands.map((c) => c.r.toolId))];
    const actionIds = [...new Set(cands.map((c) => c.r.actionId))];
    const askKeys = [...new Set(cands.map((c) => c.askKey))];
    const [spentRows, priorRows, grantRows] = await Promise.all([
      client.hostRuleOffer.findMany({
        where: {
          hostId: { in: hostIds },
          toolId: { in: toolIds },
          actionId: { in: actionIds },
          scope: { in: cands.map((c) => c.scope) },
        },
        select: { hostId: true, toolId: true, actionId: true, scope: true },
      }),
      client.hostApproval.findMany({
        where: {
          hostId: { in: hostIds },
          toolId: { in: toolIds },
          actionId: { in: actionIds },
          status: 'APPROVED',
          decision: { in: ['approve_once', 'approve_8h'] },
          decidedBy: { not: null },
          highRisk: false,
          askKey: { in: askKeys },
          decidedAt: { gte: new Date(now.getTime() - OFFER_WINDOW_MS) },
        },
        select: {
          hostId: true,
          toolId: true,
          actionId: true,
          askKey: true,
          resource: true,
        },
        orderBy: { decidedAt: 'desc' },
        take: Math.min(200 * cands.length, 2000),
      }),
      client.approvalAllowGrant.findMany({
        where: {
          hostId: { in: hostIds },
          toolId: { in: toolIds },
          actionId: { in: actionIds },
          effect: 'ALLOW',
          revokedAt: null,
          expiresAt: { gt: now },
          resourcePattern: { not: null },
          askKey: { in: askKeys },
        },
        select: {
          hostId: true,
          toolId: true,
          actionId: true,
          askKey: true,
          resourcePattern: true,
        },
        take: 500,
      }),
    ]);
    const k = (...p: Array<string | null>) => p.join('\u0000');
    const spent = new Set(
      spentRows.map((x) => k(x.hostId, x.toolId, x.actionId, x.scope)),
    );
    for (const { r, scope, askKey } of cands) {
      if (spent.has(k(r.hostId, r.toolId, r.actionId, scope))) continue;
      const approvals = priorRows.filter(
        (p) =>
          p.hostId === r.hostId &&
          p.toolId === r.toolId &&
          p.actionId === r.actionId &&
          p.askKey === askKey &&
          scopeFor(r.toolId, r.actionId, p.resource) === scope,
      ).length;
      if (approvals < OFFER_AFTER_APPROVALS) continue;
      // Already covered by an always-allow scope: nothing to offer.
      const covered = grantRows.some(
        (g) =>
          g.hostId === r.hostId &&
          g.toolId === r.toolId &&
          g.actionId === r.actionId &&
          g.askKey === askKey &&
          scopeMatches(g.resourcePattern!, r.toolId, r.actionId, r.resource),
      );
      if (covered) continue;
      out.set(r.id, {
        scope,
        approvals,
        lastsDays: Math.round(ALWAYS_GRANT_TTL_MS / 86_400_000),
        askKey,
      });
    }
    return out;
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
      include: { host: { select: { hostname: true, ownerSubject: true } } },
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
    // Founder decisions, 3 Nov 2026 (decision-rights.ts): an approver decides anything, but not a
    // sensitive request from their own device in a company workspace; the device's owner answers
    // their own routine requests in the signed-in console only. Off the console (WARDEN on the
    // device, push, Telegram) only an approver decides: a process on the device can answer a
    // device prompt, so the device credential alone is never consent. Checked here, where every
    // channel arrives, so no caller can skip it.
    const admin = await this.approvers.canApprove(
      tenantId,
      client,
      input.subject,
    );
    if (input.via !== 'console' && !admin)
      throw new ForbiddenException(
        'Answer this in the Manar console. Only a workspace approver can answer from a device or a phone. Nothing was changed.',
      );
    const owner = await client.host.findUnique({
      where: { id: row.hostId },
      select: { ownerSubject: true },
    });
    const ws = await this.approvers.workspace(tenantId);
    const rights = decisionRights({
      admin,
      owner:
        !!owner?.ownerSubject &&
        owner.ownerSubject === input.subject &&
        (admin || input.ownerMayOperate === true),
      adminsOnly: ws.adminsOnly,
      company: ws.company,
      sensitive: sensitiveReason(row),
      actionId: row.actionId,
    });
    if (!rights.choices.includes(input.decision))
      throw new ForbiddenException(refusalMessage(rights));
    // Self-approval of something sensitive (personal workspace): only in the signed-in console,
    // and only right after a fresh sign-in, checked here on the server.
    const selfConfirmed = rights.stepUp && input.decision !== 'deny';
    if (selfConfirmed && input.via !== 'console')
      throw new ForbiddenException(
        'Approving your own high-risk request needs the Manar console. Nothing was changed.',
      );
    if (selfConfirmed && !input.freshSignIn)
      throw new UnauthorizedException({
        statusCode: 401,
        code: 'reauth_required',
        maxAge: STEP_UP_MAX_AGE_SECONDS,
        message:
          'Confirm it is you (sign in again) to approve your own high-risk request. Nothing was changed.',
      });
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
    const takesOffer =
      input.alwaysAllowHere === true && input.decision !== 'deny';
    // Standing permission: console only, and only for someone who may give 8 hours (the same
    // rights, so a personal self-approval of something sensitive can never make a rule).
    if (takesOffer && input.via !== 'console')
      throw new ForbiddenException('eight_hours_in_console');
    if (takesOffer && !rights.choices.includes('approve_8h'))
      throw new ForbiddenException(refusalMessage(rights));
    // Recomputed here, never trusted from the client.
    const offer =
      (await this.offersFor(client, [row], at ?? new Date())).get(row.id) ??
      null;
    if (takesOffer && !offer)
      throw new BadRequestException('no_rule_offer_for_this_request');
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
          ...(selfConfirmed ? { selfConfirmedAt: now } : {}),
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
      // The offer is made once: any answer spends it.
      if (offer)
        await tx.hostRuleOffer.upsert({
          where: {
            hostId_toolId_actionId_scope: {
              hostId: row.hostId,
              toolId: row.toolId,
              actionId: row.actionId,
              scope: offer.scope,
            },
          },
          create: {
            hostId: row.hostId,
            toolId: row.toolId,
            actionId: row.actionId,
            scope: offer.scope,
          },
          update: {},
        });
      if (takesOffer && offer) {
        const g = await createAllowGrant(tx, {
          scope: { hostId: row.hostId },
          target: {
            toolId: row.toolId,
            actionId: row.actionId,
            resource: row.resource,
          },
          createdBy: input.subject,
          sourceId: row.id,
          now,
          always: {
            origin: 'offer',
            pattern: offer.scope,
            askKey: offer.askKey,
          },
        });
        return { grantId: g.id, origin: 'offer', scope: offer.scope };
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
        ...(row.askKey ? { askKey: row.askKey } : {}),
      });
      return { grantId: grant.id, origin: 'approval', scope: null };
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
        // "Self-approved, high risk, re-confirmed".
        ...(selfConfirmed
          ? { selfApproved: true, sensitive: rights.why, reconfirmed: true }
          : {}),
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
          origin: result.origin ?? 'approval',
          ...(result.scope ? { scope: result.scope } : {}),
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
