import {
  Injectable,
  Logger,
  Optional,
  Inject,
  forwardRef,
} from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import { PlatformKillSwitchService } from './platform-kill-switch.service';
import { EdgePeerService } from '../edge/edge-peer.service';
import { KillSwitchEpochService } from './kill-switch-epoch.service';

/** The four tenant-scoped kill-switch levels — see `KillSwitch` in `prisma/tenant.prisma`. */
export type TenantKillSwitchScope = 'TENANT' | 'AGENT_GROUP' | 'AGENT' | 'TOOL';

export interface ListKillSwitchesInput {
  scope?: TenantKillSwitchScope;
  active?: boolean;
  limit: number;
  cursor?: DecodedCursor;
}

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
  scope?: 'PLATFORM' | TenantKillSwitchScope | 'AI_SYSTEM';
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
  private readonly logger = new Logger(KillSwitchService.name);
  /** Spec §7.2 cache, keyed `tenant|agent|tool`; see `checkAll`. Bounded; oldest entry out first. */
  private readonly cache = new Map<
    string,
    { result: KillSwitchCheckResult; epoch: string; at: number }
  >();
  private static readonly CACHE_MAX_ENTRIES = 10_000;

  constructor(
    private readonly auditService: AuditService,
    private readonly platformKillSwitchService: PlatformKillSwitchService,
    // forwardRef: edge-peer.service imports the kill-switch services (an import cycle).
    @Optional()
    @Inject(forwardRef(() => EdgePeerService))
    private readonly edgePeers?: EdgePeerService,
    // Absent only in unit harnesses: no epoch store, no cache, every check reads PostgreSQL.
    @Optional() private readonly epochs?: KillSwitchEpochService,
  ) {}

  /** docs/edge.md: cut or restore the edge peers this switch covers. TOOL scope covers none. */
  private async refreshEdge(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    scope: TenantKillSwitchScope,
    targetId: string | null,
  ): Promise<void> {
    if (!this.edgePeers) return;
    if (scope === 'TENANT') return this.edgePeers.tenantChanged(tenantId);
    if (scope === 'AGENT' && targetId)
      return this.edgePeers.agentChanged(tenantId, targetId);
    if (scope === 'AGENT_GROUP' && targetId) {
      const members = await tenantClient.agentGroupMembership
        .findMany({ where: { groupId: targetId }, select: { agentId: true } })
        // A failed member lookup must not fail the switch; the tenant refresh covers the group.
        .catch(() => null);
      if (!members) return this.edgePeers.tenantChanged(tenantId);
      return this.edgePeers.agentsChanged(
        tenantId,
        members.map((m) => m.agentId),
      );
    }
  }

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
    await this.epochs?.bumpTenant(tenantId);
    await this.refreshEdge(tenantClient, tenantId, input.scope, input.targetId);

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
    await this.epochs?.bumpTenant(tenantId);
    await this.refreshEdge(tenantClient, tenantId, input.scope, input.targetId);

    return row;
  }

  /**
   * The single check `AuthorizationService.authorize` (an early pipeline
   * step, before the ancestor-chain walk — see that class's doc comment)
   * and `AuthorizationService.authorizeRedemption` (Section 32's harder
   * requirement — re-checked at redemption time, not just at issuance)
   * both call. Short-circuits on the first active switch found, in the
   * spec's own cheapest-first order.
   *
   * Spec §7.2 (docs/decision-path.md): the result is held in memory and
   * trusted only while (1) the Valkey epoch pair read now equals the one it
   * was loaded under and (2) it is younger than `maxAgeMs` (default 2 s). A
   * stale epoch rereads PostgreSQL. If the epoch cannot be read nothing is
   * trusted or cached: PostgreSQL is read directly, and if that fails the
   * call throws and the pipeline denies `enforcement_dependency_unavailable`.
   */
  async checkAll(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    params: KillSwitchCheckParams,
    options?: { fresh?: boolean },
  ): Promise<KillSwitchCheckResult> {
    const epochs = this.epochs;
    // `fresh`: stored state (edge peers) is recomputed from PostgreSQL, never from the cache.
    if (!epochs || epochs.maxAgeMs === 0 || options?.fresh) {
      return this.loadAll(tenantClient, params);
    }
    let epoch: string;
    try {
      epoch = await epochs.read(tenantId);
    } catch (error) {
      this.logger.warn(
        `Kill-switch epoch unreadable; reading PostgreSQL uncached: ${error instanceof Error ? error.message : String(error)}`,
      );
      return this.loadAll(tenantClient, params);
    }
    const key = `${tenantId}|${params.agentId}|${params.toolId ?? ''}`;
    const hit = this.cache.get(key);
    if (
      hit &&
      hit.epoch === epoch &&
      performance.now() - hit.at <= epochs.maxAgeMs
    ) {
      return hit.result;
    }
    const at = performance.now();
    const result = await this.loadAll(tenantClient, params);
    this.cache.delete(key);
    this.cache.set(key, { result, epoch, at });
    if (this.cache.size > KillSwitchService.CACHE_MAX_ENTRIES) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    return result;
  }

  private async loadAll(
    tenantClient: TenantPrismaClient,
    params: KillSwitchCheckParams,
  ): Promise<KillSwitchCheckResult> {
    if (await this.platformKillSwitchService.isActive()) {
      return {
        killed: true,
        scope: 'PLATFORM',
        reason: 'platform_kill_switch_active',
      };
    }

    // Any active TENANT row stops the tenant: the humans' switch (targetId null) and the
    // platform's own suspension switch (ADR-0010) are separate rows.
    const tenantSwitch = await tenantClient.killSwitch.findFirst({
      where: { scope: 'TENANT', active: true },
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

    // ADR-0009: a quarantined agent is stopped like a killed one. Unique
    // index on `agentId`, PostgreSQL only.
    const quarantine = await tenantClient.agentQuarantine.findFirst({
      where: { agentId: params.agentId, active: true },
      select: { id: true },
    });
    if (quarantine) {
      return { killed: true, scope: 'AGENT', reason: 'agent_quarantined' };
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

    // CLAUDE.md §7: `GovernanceState SUSPENDED` -> `RuntimeState BLOCKED`, and
    // §3's demo chain steps 18-20 ("Governance Manager suspends the AI system
    // -> further governed actions blocked"). Phase 0 finding N2 was that
    // nothing read the governance state at authorization time, so suspending
    // an AI system changed a column and stopped no agent.
    //
    // This is DERIVED from `AiSystem.lifecycleState`, not mirrored into a
    // `KillSwitch` row, and deliberately so: two facts can disagree — a
    // suspend that forgets to write the row, or a row that outlives the
    // suspend — and a governance control that can silently drift out of
    // agreement with the runtime is precisely the "monitored vs enforced"
    // confusion CLAUDE.md §5.16 names. One fact cannot drift.
    //
    // Both queries are indexed (`ai_system_agent_links(agentId)` and the
    // `AiSystem` primary key) and hit PostgreSQL only, which ADR-004 permits
    // on the decision path.
    const links = await tenantClient.aiSystemAgentLink.findMany({
      where: { agentId: params.agentId },
      select: { aiSystemId: true },
    });
    if (links.length > 0) {
      // An agent may belong to more than one AI system. The strictest state
      // wins: if any owning system is suspended or retired, the agent stops.
      const blocking = await tenantClient.aiSystem.findMany({
        where: {
          id: { in: links.map((link) => link.aiSystemId) },
          lifecycleState: { in: ['SUSPENDED', 'RETIRED'] },
        },
        select: { id: true, lifecycleState: true },
      });
      if (blocking.length > 0) {
        // SUSPENDED is reversible and RETIRED is not, so an operator reading
        // the reason needs to know which one stopped the call.
        const suspended = blocking.some(
          (system) => system.lifecycleState === 'SUSPENDED',
        );
        return {
          killed: true,
          scope: 'AI_SYSTEM',
          reason: suspended ? 'ai_system_suspended' : 'ai_system_retired',
        };
      }
    }

    return { killed: false };
  }

  /**
   * ADR-0009: every per-agent stop condition for an agent that is not the
   * caller (an ancestor in a delegation chain): the agent itself must be
   * ACTIVE (not revoked, killed or pending; the mTLS guard enforces this for
   * the caller), then everything `checkAll` enforces (kill switches at every
   * scope, quarantine, AI-system SUSPENDED/RETIRED). One definition, so a
   * stop condition added to `checkAll` later cascades too. Throws on a
   * lookup failure; callers fail closed.
   */
  async checkAgent(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    agentId: string,
    options?: { fresh?: boolean },
  ): Promise<KillSwitchCheckResult> {
    const agent = await tenantClient.agent.findUnique({
      where: { id: agentId },
      select: { status: true },
    });
    if (!agent)
      return { killed: true, scope: 'AGENT', reason: 'agent_not_found' };
    if (agent.status !== 'ACTIVE') {
      return {
        killed: true,
        scope: 'AGENT',
        reason: `agent_status_${agent.status.toLowerCase()}`,
      };
    }
    return this.checkAll(tenantClient, tenantId, { agentId }, options);
  }

  /**
   * `GET /kill-switches` (Phase 11b Part 1) — cursor-paginated, newest
   * first, with the two filters a kill-switch admin table actually needs
   * (`scope`, `active` — Section 66's kill-switch surface is "show me
   * what's currently killed," not a general browse of every row ever
   * created). Tenant-scoped, platform scope excluded (that's the control-
   * DB singleton `PlatformKillSwitch` row, with no `id`/list semantics of
   * its own — see `PlatformKillSwitchStatusResponseDto`).
   */
  async list(tenantClient: TenantPrismaClient, input: ListKillSwitchesInput) {
    const where = {
      ...(input.scope ? { scope: input.scope } : {}),
      ...(input.active !== undefined ? { active: input.active } : {}),
      ...cursorWhereClause('createdAt', input.cursor),
    };
    const rows = await tenantClient.killSwitch.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
    });
    return toCursorPage(rows, input.limit, (row) => row.createdAt);
  }
}
