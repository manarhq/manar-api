import { Injectable, Optional, Inject, forwardRef } from '@nestjs/common';
import { KillSwitchEpochService } from './kill-switch-epoch.service';
import { EdgePeerService } from '../edge/edge-peer.service';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type {
  AgentQuarantine,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { failClosed } from '../common/fail-closed/fail-closed';

export interface QuarantineInput {
  agentId: string;
  reason: string;
  detector?: string;
  evidence: string[];
  explanation?: { en: string; ar: string };
  /** The agent asking (the watcher). */
  byAgentId: string;
  decisionId: string;
  taskId: string;
}

export type QuarantineOutcome =
  | { result: 'agent_not_found' }
  | { result: 'quarantine_rate_exceeded' }
  | {
      result: 'quarantined' | 'already_quarantined';
      quarantine: AgentQuarantine;
      explanationAttached: boolean;
    };

/**
 * ADR-0009. Quarantine only ever goes one way from an agent: `quarantine`
 * sets `active = true`; `attachExplanation` adds the model's text to a
 * still-active quarantine once;
 * `release`, the only way back, is called from the human-only controller.
 * `KillSwitchService.checkAll` reads the row on every decision.
 */
@Injectable()
export class AgentQuarantineService {
  constructor(
    private readonly auditService: AuditService,
    private readonly config: ConfigService<AppConfig, true>,
    // forwardRef: edge-peer.service imports the kill-switch services (an import cycle).
    @Optional()
    @Inject(forwardRef(() => EdgePeerService))
    private readonly edgePeers?: EdgePeerService,
    @Optional() private readonly epochs?: KillSwitchEpochService,
  ) {}

  async quarantine(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: QuarantineInput,
  ): Promise<QuarantineOutcome> {
    // The tenant database is the scope: an id from another tenant is not here.
    const agent = await tenantClient.agent.findUnique({
      where: { id: input.agentId },
      select: { id: true },
    });
    if (!agent) return { result: 'agent_not_found' };

    const now = new Date();
    const windowMs =
      this.config.get('QUARANTINE_WINDOW_MS', { infer: true }) ?? 600_000;
    const cap =
      this.config.get('QUARANTINE_MAX_PER_AGENT', { infer: true }) ?? 5;
    const fresh = {
      active: true,
      reason: input.reason,
      detector: input.detector ?? null,
      evidence: input.evidence,
      explanationEn: input.explanation?.en ?? null,
      explanationAr: input.explanation?.ar ?? null,
      quarantinedByAgentId: input.byAgentId,
      decisionId: input.decisionId,
      quarantinedAt: now,
      releasedBy: null,
      releasedAt: null,
      releaseNote: null,
    };

    // One transaction, serialized per quarantining agent and per target
    // (advisory locks, always taken in that order, so no deadlock): the
    // cap count, the idempotency check and the write cannot interleave with
    // a concurrent call, so N parallel calls cannot all pass the cap and two
    // calls for one target produce one quarantine and one audit event.
    const step = await tenantClient.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT 1 FROM pg_advisory_xact_lock(hashtext(${`quarantine-by:${tenantId}:${input.byAgentId}`}))`;
      await tx.$queryRaw`SELECT 1 FROM pg_advisory_xact_lock(hashtext(${`quarantine-of:${tenantId}:${input.agentId}`}))`;
      const existing = await tx.agentQuarantine.findUnique({
        where: { agentId: input.agentId },
      });
      if (existing?.active) {
        return { result: 'already_quarantined' as const, row: existing };
      }
      // Server-side cap on how many agents one agent can stop (a buggy or
      // hijacked watcher): those it quarantined within the window, active
      // or released.
      const recent = await tx.agentQuarantine.count({
        where: {
          quarantinedByAgentId: input.byAgentId,
          quarantinedAt: { gt: new Date(now.getTime() - windowMs) },
        },
      });
      if (recent >= cap) return { result: 'quarantine_rate_exceeded' as const };
      const row = existing
        ? await tx.agentQuarantine.update({
            where: { agentId: input.agentId },
            data: fresh,
          })
        : await tx.agentQuarantine.create({
            data: { agentId: input.agentId, ...fresh },
          });
      return { result: 'quarantined' as const, row };
    });

    if (step.result === 'quarantine_rate_exceeded') return step;
    if (step.result === 'already_quarantined') {
      return {
        result: 'already_quarantined',
        quarantine: step.row,
        explanationAttached: false,
      };
    }
    const row = step.row;
    // docs/edge.md: cut the agent's network path right after the quarantine commits.
    await this.epochs?.bumpTenant(tenantId);
    await this.edgePeers?.agentChanged(tenantId, input.agentId);
    // Tightening is never held back by an audit failure; the row is the
    // control and the decision is already recorded.
    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.AGENT_QUARANTINED,
      actor: { type: 'agent', id: input.byAgentId },
      data: {
        quarantineId: row.id,
        targetAgentId: input.agentId,
        reason: input.reason,
        detector: input.detector ?? null,
        evidence: input.evidence,
        explanation: input.explanation ?? null,
        decisionId: input.decisionId,
        taskId: input.taskId,
      },
    });
    return {
      result: 'quarantined',
      quarantine: row,
      explanationAttached: input.explanation !== undefined,
    };
  }

  /**
   * Attach the model's explanation to one specific quarantine, once. Only
   * the agent that quarantined, only while that quarantine is still active,
   * only if none is attached yet. Never creates or reactivates anything, so
   * a human release that lands first stays released.
   */
  async attachExplanation(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: {
      quarantineId: string;
      agentId: string;
      byAgentId: string;
      explanation: { en: string; ar: string };
      decisionId: string;
      taskId: string;
    },
  ): Promise<boolean> {
    const attached = await tenantClient.agentQuarantine.updateMany({
      where: {
        id: input.quarantineId,
        agentId: input.agentId,
        active: true,
        explanationEn: null,
        quarantinedByAgentId: input.byAgentId,
      },
      data: {
        explanationEn: input.explanation.en,
        explanationAr: input.explanation.ar,
      },
    });
    if (attached.count === 0) return false;
    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.AGENT_QUARANTINE_EXPLAINED,
      actor: { type: 'agent', id: input.byAgentId },
      data: {
        quarantineId: input.quarantineId,
        targetAgentId: input.agentId,
        explanation: input.explanation,
        decisionId: input.decisionId,
        taskId: input.taskId,
      },
    });
    return true;
  }

  /**
   * Human only (the controller is JWT + role). Loosening fails closed: if
   * the audit event cannot be written, the release is undone and the caller
   * gets 503.
   */
  async release(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: { agentId: string; releasedBy: string; note?: string },
  ): Promise<AgentQuarantine | null> {
    const now = new Date();
    const released = await tenantClient.agentQuarantine.updateMany({
      where: { agentId: input.agentId, active: true },
      data: {
        active: false,
        releasedBy: input.releasedBy,
        releasedAt: now,
        releaseNote: input.note ?? null,
      },
    });
    if (released.count === 0) return null;
    const row = await tenantClient.agentQuarantine.findUniqueOrThrow({
      where: { agentId: input.agentId },
    });
    try {
      await failClosed('audit-store', () =>
        this.auditService.record(tenantClient, tenantId, {
          eventType: AUDIT_EVENT_TYPES.AGENT_QUARANTINE_RELEASED,
          actor: { type: 'human', id: input.releasedBy },
          data: {
            quarantineId: row.id,
            targetAgentId: input.agentId,
            reason: row.reason,
            quarantinedByAgentId: row.quarantinedByAgentId,
            quarantinedAt: row.quarantinedAt,
            note: input.note ?? null,
          },
        }),
      );
    } catch (error) {
      await tenantClient.agentQuarantine.update({
        where: { agentId: input.agentId },
        data: {
          active: true,
          releasedBy: null,
          releasedAt: null,
          releaseNote: null,
        },
      });
      throw error;
    } finally {
      // Restores the peer only if nothing else still stops the agent (or keeps it cut after the
      // rollback above).
      await this.epochs?.bumpTenant(tenantId);
      await this.edgePeers?.agentChanged(tenantId, input.agentId);
    }
    return row;
  }

  list(tenantClient: TenantPrismaClient, active?: boolean) {
    return tenantClient.agentQuarantine.findMany({
      where: active === undefined ? {} : { active },
      orderBy: { quarantinedAt: 'desc' },
      take: 100,
    });
  }
}
