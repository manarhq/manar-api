import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { z } from 'zod';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  findLiveAllowGrant,
  markAllowGrantUsed,
} from '../approvals/allow-grants';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { PolicyEngine } from '../policy/policy-engine.service';
import { KNOWN_HOST_TOOL_IDS, hostActionRisk } from '../tools/host-actions';
import type { HostContext } from '../host-mtls/host-context';

/** `POST /host/v1/authorize`: the `/agent/v1/authorize` body without a task (a device has none). */
export const HostAuthorizeSchema = z.object({
  taskId: z.string().max(128).optional(),
  /** Who called the device's local relay (`uid:1000`, `sid:S-1-5-21-...`), as the OS reported it. */
  caller: z.string().max(128).optional(),
  toolId: z.string().min(1).max(128),
  actionId: z.string().min(1).max(128),
  resource: z.string().min(1).max(2048),
});
export type HostAuthorizeRequest = z.infer<typeof HostAuthorizeSchema>;

export interface HostAuthorizeDecision {
  decision: 'ALLOW' | 'DENY' | 'APPROVAL_REQUIRED';
  reason?: string;
  riskScore?: number;
  approvalId?: string;
  expiresAt?: Date;
  /** Set when a live "Approve for 8 hours" grant turned an approval requirement into ALLOW. */
  grantId?: string;
}

/** Same as the default task ceiling for Claude Code: reads and fetches run, edits and shell ask. */
export const HOST_RISK_CEILING = 20;

/** The approvals track provides this to open a host approval; absent, APPROVAL_REQUIRED has no id. */
export const HOST_APPROVAL_OPENER = Symbol('HOST_APPROVAL_OPENER');
export interface HostApprovalOpener {
  open(
    host: HostContext,
    request: HostAuthorizeRequest,
    decision: { reason: string; riskScore: number },
  ): Promise<{ id: string; expiresAt: Date } | null>;
}

/**
 * The decision for an action of a non-Claude AI tool on an enrolled device. Order: device
 * approved, tool in the catalogue, kill switches, the tenant's published policies (its active
 * preset), and for an action no rule matched the catalogue risk against HOST_RISK_CEILING.
 * Any failure is a DENY (fail closed). The host and tenant come from the verified certificate only.
 */
@Injectable()
export class HostAuthorizeService {
  private readonly logger = new Logger(HostAuthorizeService.name);

  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly killSwitches: KillSwitchService,
    private readonly policy: PolicyEngine,
    private readonly audit: AuditService,
    @Optional()
    @Inject(HOST_APPROVAL_OPENER)
    private readonly approvals?: HostApprovalOpener,
  ) {}

  async authorize(
    host: HostContext,
    request: HostAuthorizeRequest,
  ): Promise<HostAuthorizeDecision> {
    let result: HostAuthorizeDecision;
    let client;
    try {
      client = await this.tenants.getClient(host.tenantId);
      result = await this.decide(client, host, request);
    } catch (error) {
      this.logger.error(
        `host authorize failed closed: ${error instanceof Error ? error.message : String(error)}`,
      );
      return { decision: 'DENY', reason: 'enforcement_dependency_unavailable' };
    }
    if (result.decision === 'APPROVAL_REQUIRED' && this.approvals) {
      try {
        const a = await this.approvals.open(host, request, {
          reason: result.reason ?? 'policy_requires_approval',
          riskScore: result.riskScore ?? 0,
        });
        if (a) result = { ...result, approvalId: a.id, expiresAt: a.expiresAt };
      } catch (error) {
        this.logger.warn(
          `host approval could not be opened: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    if (result.grantId) {
      // Counting a use must not change the answer; the audit record below is what matters.
      await markAllowGrantUsed(client, result.grantId).catch((error: unknown) =>
        this.logger.error(
          `could not count use of allow grant: ${error instanceof Error ? error.message : String(error)}`,
        ),
      );
      await this.audit.recordSafely(client, host.tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_USED,
        actor: { type: 'system', id: `host:${host.hostId}` },
        data: {
          grantId: result.grantId,
          hostId: host.hostId,
          toolId: request.toolId,
          actionId: request.actionId.toLowerCase(),
          resource: request.resource.slice(0, 512),
        },
      });
    }
    // The audit record is the evidence of governance: no record, no ALLOW.
    const recorded = await this.audit.recordSafely(client, host.tenantId, {
      eventType: AUDIT_EVENT_TYPES.HOST_ACTION_DECIDED,
      actor: { type: 'system', id: `host:${host.hostId}` },
      data: {
        hostId: host.hostId,
        toolId: request.toolId,
        actionId: request.actionId,
        resource: request.resource.slice(0, 512),
        decision: result.decision,
        reason: result.reason ?? null,
        riskScore: result.riskScore ?? null,
        approvalId: result.approvalId ?? null,
        caller: request.caller ?? null,
      },
    });
    if (!recorded && result.decision === 'ALLOW') {
      return { decision: 'DENY', reason: 'enforcement_dependency_unavailable' };
    }
    return result;
  }

  private async decide(
    client: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    host: HostContext,
    request: HostAuthorizeRequest,
  ): Promise<HostAuthorizeDecision> {
    if (host.status !== 'APPROVED')
      return { decision: 'DENY', reason: 'host_not_approved' };
    if (!KNOWN_HOST_TOOL_IDS.includes(request.toolId))
      return { decision: 'DENY', reason: 'unknown_tool' };
    const actionId = request.actionId.toLowerCase();
    const base = hostActionRisk(request.toolId, actionId);
    if (base === null) return { decision: 'DENY', reason: 'unknown_action' };

    const kill = await this.killSwitches.checkAll(client, host.tenantId, {
      agentId: host.hostId,
      toolId: request.toolId,
    });
    if (kill.killed)
      return { decision: 'DENY', reason: kill.reason ?? 'kill_switch' };

    // "Approve for 8 hours" (spec 4.6): looked up before the policy runs, used only to satisfy an
    // approval requirement below. A policy DENY and the kill switches above are never overridden.
    const grant = await findLiveAllowGrant(
      client,
      { hostId: host.hostId },
      { toolId: request.toolId, actionId, resource: request.resource },
    );
    const policy = await this.policy.evaluate(client, host.tenantId, {
      toolId: request.toolId,
      actionId,
      resource: request.resource,
    });
    if (policy.effect === 'DENY') {
      return {
        decision: 'DENY',
        reason: policy.failureReason
          ? 'policy_evaluation_failed'
          : 'policy_denied',
      };
    }
    if (policy.effect === 'APPROVAL_REQUIRED') {
      if (grant)
        return { decision: 'ALLOW', riskScore: base, grantId: grant.id };
      return {
        decision: 'APPROVAL_REQUIRED',
        reason: 'policy_requires_approval',
        riskScore: base,
      };
    }
    if (!policy.matchedRule && base > HOST_RISK_CEILING) {
      if (grant)
        return { decision: 'ALLOW', riskScore: base, grantId: grant.id };
      return {
        decision: 'APPROVAL_REQUIRED',
        reason: 'risk_ceiling_exceeded',
        riskScore: base,
      };
    }
    return { decision: 'ALLOW', riskScore: base };
  }
}
