import { Injectable, NotFoundException } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { PushService } from '../push/push.service';
import { dbNow } from '../common/db-clock';
import { SITE_CONNECT_ACTION } from '../jail/jail-sites';
import { upsertSiteRule } from '../jail/jail-sites.service';
import { createBlock, revokeAllowGrantsFrom } from './allow-grants';
import { approvalConflict } from './approvals.errors';

/** Who revoked: the console's signed-in person. */
export interface Revoker {
  /** `UserProfile.id` (incidents and agent approvals record people by it). */
  userId: string;
  /** Keycloak subject (device approvals and grants record people by it). */
  subject: string;
}

export interface RevokeResult {
  id: string;
  status: 'REVOKED';
  /** False: cancelled before the device or agent had it, so nothing ran. True: it may have run. */
  usedBeforeRevoke: boolean;
  /** 8-hour grants and site rules this approval had created that are now withdrawn. */
  withdrawn: number;
  /** After use: the block that refuses this exact action next time, until a person lifts it. */
  blockId: string | null;
  /** After use: the incident opened for the workspace's admins. */
  incidentId: string | null;
}

const notApproved = () =>
  approvalConflict(
    'not_approved',
    'Only an approved request can be revoked. Nothing was changed.',
  );

/**
 * Revoke (founder decision, 3 Nov 2026): an approval nobody has used yet is cancelled at once and
 * the device or agent can no longer use it; one already used is marked "revoked after use", the
 * workspace's approvers are alerted (push and an incident), and that exact action is blocked next
 * time. Either way, any 8-hour grant or remembered site rule it created is withdrawn.
 *
 * "Used" is decided by one conditional update racing the device's or agent's own read
 * (`HostApprovalsService.readForDevice`, `AgentApprovalsController.get`): whichever lands first
 * wins, so the answer is never "cancelled" for something the device already saw as APPROVED.
 */
@Injectable()
export class ApprovalRevokeService {
  constructor(
    private readonly audit: AuditService,
    private readonly push: PushService,
  ) {}

  async revokeHost(
    client: TenantPrismaClient,
    tenantId: string,
    id: string,
    by: Revoker,
    note?: string,
  ): Promise<RevokeResult> {
    const row = await client.hostApproval.findUnique({ where: { id } });
    if (!row) throw new NotFoundException('That approval was not found.');
    if (row.status !== 'APPROVED') throw notApproved();
    const now = await dbNow(client);
    const fields = {
      revokedAt: now,
      revokedBy: by.subject,
      revokeNote: note ?? null,
    };
    const unused = await client.hostApproval.updateMany({
      where: { id, status: 'APPROVED', usedAt: null },
      data: { status: 'REVOKED', usedBeforeRevoke: false, ...fields },
    });
    let used = false;
    if (unused.count === 0) {
      const after = await client.hostApproval.updateMany({
        where: { id, status: 'APPROVED' },
        data: { status: 'REVOKED', usedBeforeRevoke: true, ...fields },
      });
      if (after.count === 0) throw notApproved();
      used = true;
    }

    const isSite = row.actionId === SITE_CONNECT_ACTION;
    let withdrawn = await revokeAllowGrantsFrom(client, id, now);
    if (
      isSite &&
      (row.decision === 'approve_8h' || row.decision === 'approve_always')
    ) {
      // The remembered answer for this site (the device drops it at its next config read, 20 s).
      const { count } = await client.hostSiteRule.deleteMany({
        where: {
          hostId: row.hostId,
          toolId: row.toolId,
          site: row.resource,
          source: 'approval',
          mode: 'ALLOW',
        },
      });
      withdrawn += count;
    }

    let blockId: string | null = null;
    let incidentId: string | null = null;
    if (used) {
      if (isSite) {
        // A DENY site rule: the device enforces it within one config read and it outranks the
        // device's 60-second "allow once" window. Lifted on the Sites page or from the history.
        const rule = await upsertSiteRule(client, {
          hostId: row.hostId,
          toolId: row.toolId,
          site: row.resource,
          mode: 'DENY',
          expiresAt: null,
          source: 'approval',
          createdBy: by.subject,
        });
        blockId = rule.id;
      } else {
        const block = await createBlock(client, {
          scope: { hostId: row.hostId },
          target: {
            toolId: row.toolId,
            actionId: row.actionId,
            resource: row.resource,
          },
          createdBy: by.subject,
          sourceId: id,
          now,
        });
        blockId = block.id;
      }
      incidentId = await this.alert(client, tenantId, by, {
        approvalId: id,
        what: `${row.toolId} ${row.actionId}`,
      });
    }

    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_REVOKED,
      actor: { type: 'human', id: by.userId },
      data: {
        hostApprovalId: id,
        hostId: row.hostId,
        toolId: row.toolId,
        actionId: row.actionId,
        usedBeforeRevoke: used,
        withdrawn,
        blockId,
        incidentId,
      },
    });
    return {
      id,
      status: 'REVOKED',
      usedBeforeRevoke: used,
      withdrawn,
      blockId,
      incidentId,
    };
  }

  async revokeAgent(
    client: TenantPrismaClient,
    tenantId: string,
    id: string,
    by: Revoker,
    note?: string,
  ): Promise<RevokeResult> {
    const row = await client.approvalRequest.findUnique({
      where: { id },
      include: { grant: true },
    });
    if (!row) throw new NotFoundException('That approval was not found.');
    if (row.status !== 'APPROVED') throw notApproved();
    const now = new Date();
    // Stop the one-use grant first: a REST or MCP redemption that has not happened cannot now.
    const grantStopped = row.grant
      ? (
          await client.authorizationGrant.updateMany({
            where: { id: row.grant.id, consumedAt: null, revokedAt: null },
            data: { revokedAt: now },
          })
        ).count === 1
      : true;
    const fields = {
      revokedAt: now,
      revokedBy: by.userId,
      revokeNote: note ?? null,
    };
    const unreleased = await client.approvalRequest.updateMany({
      where: { id, status: 'APPROVED', releasedAt: null },
      data: { status: 'REVOKED', usedBeforeRevoke: !grantStopped, ...fields },
    });
    let used = !grantStopped;
    if (unreleased.count === 0) {
      // The agent already read it as APPROVED (the Claude Code hook runs at that moment).
      const after = await client.approvalRequest.updateMany({
        where: { id, status: 'APPROVED' },
        data: { status: 'REVOKED', usedBeforeRevoke: true, ...fields },
      });
      if (after.count === 0) throw notApproved();
      used = true;
    }

    const withdrawn = await revokeAllowGrantsFrom(client, id, now);
    let blockId: string | null = null;
    let incidentId: string | null = null;
    if (used) {
      const block = await createBlock(client, {
        scope: { agentId: row.agentId },
        target: {
          toolId: row.toolId,
          actionId: row.actionId,
          resource: row.resource,
        },
        createdBy: by.subject,
        sourceId: id,
        now,
      });
      blockId = block.id;
      incidentId = await this.alert(client, tenantId, by, {
        approvalId: id,
        what: `${row.toolId} ${row.actionId}`,
      });
    }

    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_REVOKED,
      actor: { type: 'human', id: by.userId },
      data: {
        approvalRequestId: id,
        agentId: row.agentId,
        toolId: row.toolId,
        actionId: row.actionId,
        usedBeforeRevoke: used,
        withdrawn,
        blockId,
        incidentId,
      },
    });
    return {
      id,
      status: 'REVOKED',
      usedBeforeRevoke: used,
      withdrawn,
      blockId,
      incidentId,
    };
  }

  /**
   * Withdraws an 8-hour grant, or lifts a block, at any time. Idempotent for a grant that is
   * already withdrawn or expired (409, nothing changed).
   */
  async revokeGrant(
    client: TenantPrismaClient,
    tenantId: string,
    grantId: string,
    by: Revoker,
  ) {
    const now = new Date();
    const grant = await client.approvalAllowGrant.findUnique({
      where: { id: grantId },
    });
    if (!grant) throw new NotFoundException('That permission was not found.');
    const { count } = await client.approvalAllowGrant.updateMany({
      where: { id: grantId, revokedAt: null, expiresAt: { gt: now } },
      data: { revokedAt: now },
    });
    if (count === 0)
      throw approvalConflict(
        'not_approved',
        'This permission has already ended. Nothing was changed.',
      );
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_REVOKED,
      actor: { type: 'human', id: by.userId },
      data: {
        grantId,
        effect: grant.effect,
        hostId: grant.hostId,
        agentId: grant.agentId,
        toolId: grant.toolId,
        actionId: grant.actionId,
      },
    });
    return { id: grantId, revokedAt: now, effect: grant.effect };
  }

  /** Revoked after use: an incident the admins see, and a push to every approver. Never throws. */
  private async alert(
    client: TenantPrismaClient,
    tenantId: string,
    by: Revoker,
    input: { approvalId: string; what: string },
  ): Promise<string | null> {
    let incidentId: string | null = null;
    try {
      const incident = await client.incident.create({
        data: {
          title: `Approval revoked after it was used: ${input.what}`.slice(
            0,
            200,
          ),
          description: `An approved action (${input.what}) was revoked after the device or agent had already received it, so it may have run. Approval ${input.approvalId}. The same action is now blocked until someone lifts the block on the Approvals page.`,
          severity: 'HIGH',
          createdBy: by.userId,
        },
      });
      incidentId = incident.id;
      await this.audit.recordSafely(client, tenantId, {
        eventType: AUDIT_EVENT_TYPES.INCIDENT_CREATED,
        actor: { type: 'human', id: by.userId },
        data: { incidentId, severity: 'HIGH', relatedCorrelationIds: [] },
      });
    } catch {
      // The revoke itself stands; the audit event above records it either way.
    }
    void this.push.notifyApprovers(client, tenantId, {
      kind: 'approval_revoked',
      title: 'Manar',
      body: `Revoked after use: ${input.what}. It may have run.`,
      url: '/approvals',
      tag: `approval-revoked-${input.approvalId}`,
      approvalId: input.approvalId,
    });
    return incidentId;
  }
}
