import { Injectable } from '@nestjs/common';
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
  | {
      result: 'quarantined' | 'already_quarantined';
      quarantine: AgentQuarantine;
      explanationAttached: boolean;
    };

/**
 * ADR-0009. Quarantine only ever goes one way from an agent: `quarantine`
 * sets `active = true` (and may attach the model's explanation once);
 * `release`, the only way back, is called from the human-only controller.
 * `KillSwitchService.checkAll` reads the row on every decision.
 */
@Injectable()
export class AgentQuarantineService {
  constructor(private readonly auditService: AuditService) {}

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

    // Idempotent and race-safe: only an inactive (or missing) row flips to
    // active, so two concurrent calls produce one quarantine and one audit.
    const flipped = await tenantClient.agentQuarantine.updateMany({
      where: { agentId: input.agentId, active: false },
      data: fresh,
    });
    let created = flipped.count > 0;
    if (!created) {
      try {
        await tenantClient.agentQuarantine.create({
          data: { agentId: input.agentId, ...fresh },
        });
        created = true;
      } catch (error) {
        // P2002: a row exists (active, or a concurrent create won).
        if ((error as { code?: string }).code !== 'P2002') throw error;
      }
    }

    if (created) {
      const row = await tenantClient.agentQuarantine.findUniqueOrThrow({
        where: { agentId: input.agentId },
      });
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

    // Already active: the only change an agent may make is attaching the
    // explanation, once (`explanation IS NULL`), never rewriting it.
    let explanationAttached = false;
    if (input.explanation) {
      const attached = await tenantClient.agentQuarantine.updateMany({
        where: {
          agentId: input.agentId,
          active: true,
          explanationEn: null,
        },
        data: {
          explanationEn: input.explanation.en,
          explanationAr: input.explanation.ar,
        },
      });
      explanationAttached = attached.count > 0;
      if (explanationAttached) {
        await this.auditService.recordSafely(tenantClient, tenantId, {
          eventType: AUDIT_EVENT_TYPES.AGENT_QUARANTINE_EXPLAINED,
          actor: { type: 'agent', id: input.byAgentId },
          data: {
            targetAgentId: input.agentId,
            explanation: input.explanation,
            decisionId: input.decisionId,
            taskId: input.taskId,
          },
        });
      }
    }
    const row = await tenantClient.agentQuarantine.findUniqueOrThrow({
      where: { agentId: input.agentId },
    });
    return {
      result: 'already_quarantined',
      quarantine: row,
      explanationAttached,
    };
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
