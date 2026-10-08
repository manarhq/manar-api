import { createHash } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AgentQuarantineService } from '../kill-switches/agent-quarantine.service';
import type { ToolInvocationResult } from './tool-protocol-adapter.interface';
import { MANAR_ACTIVITY_READ, MANAR_AGENT_QUARANTINE } from './manar-actions';

export interface ManarConnectorCall {
  tenantId: string;
  taskId: string;
  /** The calling agent (mTLS identity). */
  agentId: string;
  actionId: string;
  resource: string;
  params: unknown;
  decisionId: string;
}

const ID = /^[\w.:-]{1,128}$/;

const ActivityReadParams = z
  .object({
    windowSeconds: z.number().int().min(10).max(3600).default(300),
    limit: z.number().int().min(1).max(1000).default(500),
  })
  .strict();

const QuarantineParams = z
  .object({
    reason: z.string().trim().min(1).max(500),
    detector: z
      .string()
      .regex(/^[a-z0-9_.-]{1,64}$/)
      .optional(),
    evidence: z.array(z.string().regex(ID)).max(50).default([]),
    explanation: z
      .object({
        en: z.string().trim().min(1).max(1500),
        ar: z.string().trim().min(1).max(1500),
      })
      .strict()
      .optional(),
  })
  .strict();

const BASELINE_WINDOW_MS = 24 * 3600 * 1000;

/** Distinct-count without exposing the target id (a user GUID, a host id). */
function resourceRef(resource: string): string {
  return createHash('sha256').update(resource).digest('hex').slice(0, 16);
}

const fail = (errorMessage: string): ToolInvocationResult => ({
  success: false,
  errorMessage,
});

/**
 * ADR-0009: Manar's built-in connector, run by `CredentialBrokerService` for
 * the `manar` built-in tool (`isManarBuiltin`) after the full decision pipeline allowed the call. It
 * executes only the two catalog actions and works only on the caller's own
 * tenant database. Nothing here can release a quarantine, change a kill
 * switch, policy, task, grant or approval, or delete anything.
 */
@Injectable()
export class ManarConnectorService {
  constructor(private readonly quarantineService: AgentQuarantineService) {}

  async invoke(
    tenantClient: TenantPrismaClient,
    call: ManarConnectorCall,
  ): Promise<ToolInvocationResult> {
    if (call.actionId === MANAR_ACTIVITY_READ) {
      const params = ActivityReadParams.safeParse(call.params ?? {});
      if (!params.success) return fail('invalid_params');
      return {
        success: true,
        data: await this.readActivity(tenantClient, params.data),
      };
    }
    if (call.actionId === MANAR_AGENT_QUARANTINE) {
      const params = QuarantineParams.safeParse(call.params ?? {});
      if (!params.success) return fail('invalid_params');
      const outcome = await this.quarantineService.quarantine(
        tenantClient,
        call.tenantId,
        {
          agentId: call.resource,
          reason: params.data.reason,
          detector: params.data.detector,
          evidence: params.data.evidence,
          explanation: params.data.explanation,
          byAgentId: call.agentId,
          decisionId: call.decisionId,
          taskId: call.taskId,
        },
      );
      if (outcome.result === 'agent_not_found') return fail('agent_not_found');
      return {
        success: true,
        data: {
          result: outcome.result,
          quarantineId: outcome.quarantine.id,
          agentId: outcome.quarantine.agentId,
          quarantinedAt: outcome.quarantine.quarantinedAt.toISOString(),
          explanationAttached: outcome.explanationAttached,
        },
      };
    }
    // The catalog is code: a ToolAction row with any other name never runs.
    return fail('unknown_manar_action');
  }

  /**
   * Metadata and counts only. Decisions never store parameters (only an
   * inputs hash, not returned here); resources are returned as a short hash
   * so distinct targets can be counted without exposing them.
   */
  private async readActivity(
    tenantClient: TenantPrismaClient,
    params: z.infer<typeof ActivityReadParams>,
  ) {
    const now = new Date();
    const since = new Date(now.getTime() - params.windowSeconds * 1000);
    const take = params.limit + 1;

    const [
      decisions,
      approvals,
      invocations,
      agents,
      actions,
      actionTypes,
      baseline,
    ] = await Promise.all([
      tenantClient.decision.findMany({
        where: { createdAt: { gte: since } },
        orderBy: { createdAt: 'desc' },
        take,
        select: {
          id: true,
          agentId: true,
          taskId: true,
          toolId: true,
          actionId: true,
          resource: true,
          outcome: true,
          reasonCodes: true,
          stage: true,
          createdAt: true,
        },
      }),
      tenantClient.approvalRequest.findMany({
        where: { createdAt: { gte: since } },
        orderBy: { createdAt: 'desc' },
        take,
        select: {
          id: true,
          agentId: true,
          taskId: true,
          toolId: true,
          actionId: true,
          status: true,
          createdAt: true,
        },
      }),
      tenantClient.toolInvocation.findMany({
        where: { createdAt: { gte: since } },
        orderBy: { createdAt: 'desc' },
        take,
        select: {
          id: true,
          agentId: true,
          taskId: true,
          decisionId: true,
          status: true,
          createdAt: true,
          tool: { select: { name: true } },
          action: { select: { name: true } },
        },
      }),
      tenantClient.agent.findMany({
        take: 500,
        orderBy: { createdAt: 'asc' },
        select: {
          id: true,
          slug: true,
          displayName: true,
          status: true,
          quarantine: { select: { active: true } },
        },
      }),
      tenantClient.toolAction.findMany({
        select: {
          name: true,
          mutating: true,
          destructive: true,
          tool: { select: { name: true } },
        },
      }),
      // ponytail: all-time groupBy over decisions; fine at pilot volume, move
      // to a maintained per-agent summary table if decisions reach millions.
      tenantClient.decision.groupBy({
        by: ['agentId', 'toolId', 'actionId'],
        _min: { createdAt: true },
        _count: { _all: true },
      }),
      tenantClient.decision.groupBy({
        by: ['agentId'],
        where: {
          createdAt: {
            gte: new Date(since.getTime() - BASELINE_WINDOW_MS),
            lt: since,
          },
        },
        _count: { _all: true },
      }),
    ]);

    const flags = new Map(
      actions.map((a) => [
        `${a.tool.name}/${a.name}`,
        { mutating: a.mutating, destructive: a.destructive },
      ]),
    );
    const flagsOf = (toolId: string, actionId: string) =>
      flags.get(`${toolId}/${actionId}`) ?? {
        mutating: false,
        destructive: false,
      };

    return {
      generatedAt: now.toISOString(),
      since: since.toISOString(),
      windowSeconds: params.windowSeconds,
      truncated:
        decisions.length > params.limit ||
        approvals.length > params.limit ||
        invocations.length > params.limit,
      agents: agents.map((a) => ({
        id: a.id,
        slug: a.slug,
        displayName: a.displayName,
        status: a.status,
        quarantined: a.quarantine?.active ?? false,
      })),
      decisions: decisions.slice(0, params.limit).map((d) => ({
        id: d.id,
        agentId: d.agentId,
        taskId: d.taskId,
        toolId: d.toolId,
        actionId: d.actionId,
        resourceRef: resourceRef(d.resource),
        outcome: d.outcome,
        reason: d.reasonCodes[0] ?? null,
        stage: d.stage,
        ...flagsOf(d.toolId, d.actionId),
        createdAt: d.createdAt.toISOString(),
      })),
      approvals: approvals.slice(0, params.limit).map((a) => ({
        ...a,
        createdAt: a.createdAt.toISOString(),
      })),
      invocations: invocations.slice(0, params.limit).map((i) => ({
        id: i.id,
        agentId: i.agentId,
        taskId: i.taskId,
        decisionId: i.decisionId,
        toolId: i.tool.name,
        actionId: i.action.name,
        status: i.status,
        createdAt: i.createdAt.toISOString(),
      })),
      /** Every (agent, tool, action) ever decided, with its first time: "first-ever" detection. */
      actionTypes: actionTypes.map((t) => ({
        agentId: t.agentId,
        toolId: t.toolId,
        actionId: t.actionId,
        firstSeenAt: t._min.createdAt?.toISOString() ?? null,
        count: t._count._all,
      })),
      /** Decisions per agent in the 24 h before `since`: the rate baseline. */
      baseline: {
        windowSeconds: BASELINE_WINDOW_MS / 1000,
        decisionsByAgent: Object.fromEntries(
          baseline.map((b) => [b.agentId, b._count._all]),
        ),
      },
    };
  }
}
