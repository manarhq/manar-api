import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { PlatformKillSwitchService } from './platform-kill-switch.service';

/** The four tenant-scoped kill-switch levels — see `KillSwitch` in `prisma/tenant.prisma`. */
export type TenantKillSwitchScope = 'TENANT' | 'AGENT_GROUP' | 'AGENT' | 'TOOL';

export interface ActivateKillSwitchInput {
  scope: TenantKillSwitchScope;
  /** `null` only for `TENANT` scope — see `KillSwitch.targetId`'s schema doc comment. */
  targetId: string | null;
  reason?: string;
  activatedBy: string;
}

export interface DeactivateKillSwitchInput {
  scope: TenantKillSwitchScope;
  targetId: string | null;
  deactivatedBy: string;
}

export interface KillSwitchCheckParams {
  agentId: string;
  /** The opaque, caller-supplied `toolId` string (Phase 5's contract — may or may not resolve against a registered `Tool.name`). Omit when the pipeline doesn't yet know which tool is being invoked (see docs/kill-switches.md). */
  toolId?: string | null;
}

export interface KillSwitchCheckResult {
  killed: boolean;
  /** Present only when `killed` is true. */
  scope?: 'PLATFORM' | TenantKillSwitchScope;
  /** Present only when `killed` is true — a specific, non-leaky reason (app-layer deterministic state, safe to expose — same posture as `AuthorizationService`'s steps 1-4). */
  reason?: string;
}

/**
 * Kill-switch phase (Section 32) — see docs/kill-switches.md.
 *
 * Owns the four tenant-scoped `KillSwitch` rows (activate/deactivate,
 * each writing a `kill_switch.activated`/`kill_switch.deactivated`
 * `AuditEvent` via `AuditService.recordSafely`) AND the read-side
 * `checkAll` orchestration `AuthorizationService`/`GrantService` call on
 * their respective hot paths — one implementation of "is this
 * agent/tool/tenant/platform currently killed," not two copies that could
 * drift between the authorize pipeline and grant redemption.
 *
 * Checked in the cheapest-first order the design spec specifies: platform
 * (control DB, applies to literally everything) → tenant → agent →
 * agent-group(s) → tool (only when a `toolId` is given and it resolves
 * against a real registered `Tool` — an unregistered/opaque `toolId` has
 * no `Tool.id` for a `TOOL`-scope switch to ever target, so it's simply
 * never killed, matching this codebase's existing "opaque toolId, only
 * *may* resolve against the registry" contract — see `ToolRegistryService`'s
 * doc comment).
 */
@Injectable()
export class KillSwitchService {
  constructor(
    private readonly auditService: AuditService,
    private readonly platformKillSwitchService: PlatformKillSwitchService,
  ) {}

  /**
   * One row per (scope, targetId) pair, toggled in place — see `KillSwitch`'s
   * schema doc comment. Idempotent: activating an already-active switch
   * just refreshes `reason`/`activatedBy`/`activatedAt` and still audits
   * (an operator re-activating with a new reason is a real, distinct event
   * worth recording, unlike `PlatformKillSwitchService`'s own upsert, which
   * is not itself audited by that class — audit recording lives here, at
   * the one call site that actually knows the tenant).
   */
  async activate(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: ActivateKillSwitchInput,
  ) {
    const existing = await tenantClient.killSwitch.findFirst({
      where: { scope: input.scope, targetId: input.targetId },
    });
    const now = new Date();
    const row = existing
      ? await tenantClient.killSwitch.update({
          where: { id: existing.id },
          data: {
            active: true,
            reason: input.reason ?? null,
            activatedBy: input.activatedBy,
            activatedAt: now,
            deactivatedBy: null,
            deactivatedAt: null,
          },
        })
      : await tenantClient.killSwitch.create({
          data: {
            scope: input.scope,
            targetId: input.targetId,
            active: true,
            reason: input.reason ?? null,
            activatedBy: input.activatedBy,
            activatedAt: now,
          },
        });

    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.KILL_SWITCH_ACTIVATED,
      actor: { type: 'human', id: input.activatedBy },
      data: {
        killSwitchId: row.id,
        scope: input.scope,
        targetId: input.targetId,
        reason: input.reason ?? null,
      },
    });

    return row;
  }

  /** Idempotent: deactivating an already-inactive (or never-activated) switch is a no-op — returns `null` and does not audit (nothing actually changed). */
  async deactivate(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: DeactivateKillSwitchInput,
  ) {
    const existing = await tenantClient.killSwitch.findFirst({
      where: { scope: input.scope, targetId: input.targetId, active: true },
    });
    if (!existing) return null;

    const now = new Date();
    const row = await tenantClient.killSwitch.update({
      where: { id: existing.id },
      data: {
        active: false,
        deactivatedBy: input.deactivatedBy,
        deactivatedAt: now,
      },
    });

    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.KILL_SWITCH_DEACTIVATED,
      actor: { type: 'human', id: input.deactivatedBy },
      data: {
        killSwitchId: row.id,
        scope: input.scope,
        targetId: input.targetId,
      },
    });

    return row;
  }

  /**
   * The single check `AuthorizationService.authorize` (an early pipeline
   * step, before the ancestor-chain walk — see that class's doc comment)
   * and `GrantService.validateAndConsumeGrant` (Section 32's harder
   * requirement — re-checked at redemption time, not just at issuance)
   * both call. Short-circuits on the first active switch found, in the
   * spec's own cheapest-first order.
   */
  async checkAll(
    tenantClient: TenantPrismaClient,
    _tenantId: string,
    params: KillSwitchCheckParams,
  ): Promise<KillSwitchCheckResult> {
    if (await this.platformKillSwitchService.isActive()) {
      return {
        killed: true,
        scope: 'PLATFORM',
        reason: 'platform_kill_switch_active',
      };
    }

    const tenantSwitch = await tenantClient.killSwitch.findFirst({
      where: { scope: 'TENANT', targetId: null, active: true },
    });
    if (tenantSwitch) {
      return {
        killed: true,
        scope: 'TENANT',
        reason: 'tenant_kill_switch_active',
      };
    }

    const agentSwitch = await tenantClient.killSwitch.findFirst({
      where: { scope: 'AGENT', targetId: params.agentId, active: true },
    });
    if (agentSwitch) {
      return {
        killed: true,
        scope: 'AGENT',
        reason: 'agent_kill_switch_active',
      };
    }

    const memberships = await tenantClient.agentGroupMembership.findMany({
      where: { agentId: params.agentId },
      select: { groupId: true },
    });
    if (memberships.length > 0) {
      const groupSwitch = await tenantClient.killSwitch.findFirst({
        where: {
          scope: 'AGENT_GROUP',
          targetId: { in: memberships.map((m) => m.groupId) },
          active: true,
        },
      });
      if (groupSwitch) {
        return {
          killed: true,
          scope: 'AGENT_GROUP',
          reason: 'agent_group_kill_switch_active',
        };
      }
    }

    if (params.toolId) {
      const tool = await tenantClient.tool.findUnique({
        where: { name: params.toolId },
      });
      if (tool) {
        const toolSwitch = await tenantClient.killSwitch.findFirst({
          where: { scope: 'TOOL', targetId: tool.id, active: true },
        });
        if (toolSwitch) {
          return {
            killed: true,
            scope: 'TOOL',
            reason: 'tool_kill_switch_active',
          };
        }
      }
    }

    return { killed: false };
  }
}
