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
  })
  .strict();

const AttachParams = z
  .object({
    quarantineId: z.string().uuid(),
    explanation: z
      .object({
        en: z.string().trim().min(1).max(1500),
        ar: z.string().trim().min(1).max(1500),
      })
      .strict(),
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
/** Agents returned per read, most recently active first. */
const MAX_AGENTS = 200;
const MAX_EVIDENCE = 20;
/** Denials that are Manar stopping the agent, not the agent misbehaving. */
const STOPPED_REASON =
  '^(agent_quarantined|ancestor_.*|.*_kill_switch_active|ai_system_.*|agent_status_.*|enforcement_dependency_unavailable)$';

interface ActionRow {
  agentId: string;
  toolId: string;
  actionId: string;
  decisions: number;
  allowed: number;
  denied: number;
  stopped: number;
  approvalRequired: number;
  mutating: boolean;
  destructive: boolean;
  distinctResources: number;
  firstSeenAt: Date;
  lastSeenAt: Date;
  firstEverAt: Date;
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
    const attachId = (call.params as { quarantineId?: unknown } | null)
      ?.quarantineId;
    if (call.actionId === MANAR_AGENT_QUARANTINE && attachId !== undefined) {
      // Attach-only mode: never creates or reactivates a quarantine.
      const params = AttachParams.safeParse(call.params);
      if (!params.success) return fail('invalid_params');
      const attached = await this.quarantineService.attachExplanation(
        tenantClient,
        call.tenantId,
        {
          quarantineId: params.data.quarantineId,
          agentId: call.resource,
          byAgentId: call.agentId,
          explanation: params.data.explanation,
          decisionId: call.decisionId,
          taskId: call.taskId,
        },
      );
      return {
        success: true,
        data: {
          result: attached ? 'explanation_attached' : 'not_attached',
          quarantineId: params.data.quarantineId,
          agentId: call.resource,
          explanationAttached: attached,
        },
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
      if (outcome.result === 'quarantine_rate_exceeded') {
        return fail('quarantine_rate_exceeded');
      }
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
   * Per-agent aggregates for the window, computed in PostgreSQL, so one busy
   * agent cannot push another out of the snapshot. Counts and action names
   * only: no parameters, no resources (not even hashed; distinct targets are
   * counted server side). An agent's window starts after its last
   * quarantine release, so a human release is not undone by the evidence
   * that caused it, whatever the watcher remembers.
   */
  private async readActivity(
    tenantClient: TenantPrismaClient,
    params: z.infer<typeof ActivityReadParams>,
  ) {
    const now = new Date();
    const since = new Date(now.getTime() - params.windowSeconds * 1000);

    // ponytail: the firstEverAt subquery uses decisions(agentId, createdAt);
    // fine at pilot volume, a per-agent summary table if decisions reach millions.
    const actions = await tenantClient.$queryRaw<ActionRow[]>`
      WITH w AS (
        SELECT d.*, a.mutating AS a_mutating, a.destructive AS a_destructive
        FROM decisions d
        LEFT JOIN agent_quarantines q ON q."agentId" = d."agentId"
        LEFT JOIN tools t ON t.name = d."toolId"
        LEFT JOIN tool_actions a ON a."toolId" = t.id AND a.name = d."actionId"
        WHERE d."createdAt" >= ${since}
          AND (q."releasedAt" IS NULL OR d."createdAt" > q."releasedAt")
      )
      SELECT "agentId", "toolId", "actionId",
        COUNT(*)::int AS decisions,
        COUNT(*) FILTER (WHERE outcome = 'ALLOW')::int AS allowed,
        COUNT(*) FILTER (WHERE outcome = 'DENY'
          AND COALESCE("reasonCodes"[1], '') !~ ${STOPPED_REASON})::int AS denied,
        COUNT(*) FILTER (WHERE outcome = 'DENY'
          AND COALESCE("reasonCodes"[1], '') ~ ${STOPPED_REASON})::int AS stopped,
        COUNT(*) FILTER (WHERE outcome = 'APPROVAL_REQUIRED')::int AS "approvalRequired",
        COALESCE(bool_or(a_mutating), false) AS mutating,
        COALESCE(bool_or(a_destructive), false) AS destructive,
        COUNT(DISTINCT resource)::int AS "distinctResources",
        MIN("createdAt") AS "firstSeenAt",
        MAX("createdAt") AS "lastSeenAt",
        (SELECT MIN(d2."createdAt") FROM decisions d2
          WHERE d2."agentId" = w."agentId" AND d2."toolId" = w."toolId"
            AND d2."actionId" = w."actionId") AS "firstEverAt"
      FROM w
      GROUP BY "agentId", "toolId", "actionId"`;

    const lastActive = new Map<string, number>();
    for (const a of actions) {
      lastActive.set(
        a.agentId,
        Math.max(lastActive.get(a.agentId) ?? 0, a.lastSeenAt.getTime()),
      );
    }
    const ranked = [...lastActive.entries()].sort((x, y) => y[1] - x[1]);
    const ids = ranked.slice(0, MAX_AGENTS).map(([id]) => id);
    const truncated = ranked.length > MAX_AGENTS;
    if (ids.length === 0) {
      return {
        generatedAt: now.toISOString(),
        since: since.toISOString(),
        windowSeconds: params.windowSeconds,
        truncated: false,
        agents: [],
      };
    }

    const [agents, targets, evidence, baseline, approvals, invocations] =
      await Promise.all([
        tenantClient.agent.findMany({
          where: { id: { in: ids } },
          select: {
            id: true,
            slug: true,
            displayName: true,
            status: true,
            quarantine: { select: { active: true, releasedAt: true } },
          },
        }),
        tenantClient.$queryRaw<{ agentId: string; n: number }[]>`
          SELECT d."agentId", COUNT(DISTINCT d.resource)::int AS n
          FROM decisions d
          JOIN tools t ON t.name = d."toolId"
          JOIN tool_actions a ON a."toolId" = t.id AND a.name = d."actionId"
          LEFT JOIN agent_quarantines q ON q."agentId" = d."agentId"
          WHERE d."createdAt" >= ${since} AND a.mutating
            AND d."agentId" = ANY(${ids})
            AND (q."releasedAt" IS NULL OR d."createdAt" > q."releasedAt")
          GROUP BY 1`,
        tenantClient.$queryRaw<{ agentId: string; id: string }[]>`
          SELECT "agentId", id FROM (
            SELECT d."agentId", d.id, row_number() OVER (
              PARTITION BY d."agentId"
              ORDER BY (d.outcome = 'DENY') DESC, d."createdAt" DESC) AS rn
            FROM decisions d
            LEFT JOIN agent_quarantines q ON q."agentId" = d."agentId"
            WHERE d."createdAt" >= ${since} AND d."agentId" = ANY(${ids})
              AND (q."releasedAt" IS NULL OR d."createdAt" > q."releasedAt")
          ) x WHERE rn <= ${MAX_EVIDENCE}`,
        tenantClient.decision.groupBy({
          by: ['agentId'],
          where: {
            agentId: { in: ids },
            createdAt: {
              gte: new Date(since.getTime() - BASELINE_WINDOW_MS),
              lt: since,
            },
          },
          _count: { _all: true },
        }),
        tenantClient.approvalRequest.groupBy({
          by: ['agentId', 'status'],
          where: { agentId: { in: ids }, createdAt: { gte: since } },
          _count: { _all: true },
        }),
        tenantClient.toolInvocation.groupBy({
          by: ['agentId', 'status'],
          where: { agentId: { in: ids }, createdAt: { gte: since } },
          _count: { _all: true },
        }),
      ]);

    const sum = (rows: ActionRow[], k: keyof ActionRow) =>
      rows.reduce((n, r) => n + (r[k] as number), 0);
    const byStatus = (
      rows: { agentId: string; status: string; _count: { _all: number } }[],
      agentId: string,
    ) =>
      Object.fromEntries(
        rows
          .filter((r) => r.agentId === agentId)
          .map((r) => [r.status, r._count._all]),
      );
    const info = new Map(agents.map((a) => [a.id, a]));

    return {
      generatedAt: now.toISOString(),
      since: since.toISOString(),
      windowSeconds: params.windowSeconds,
      truncated,
      ...(truncated
        ? {
            truncatedReason: `more than ${MAX_AGENTS} agents active in the window; the ${MAX_AGENTS} most recently active are returned`,
          }
        : {}),
      agents: ids.map((id) => {
        const a = info.get(id);
        const rows = actions.filter((r) => r.agentId === id);
        const releasedAt = a?.quarantine?.releasedAt ?? null;
        const windowStart =
          releasedAt && releasedAt > since ? releasedAt : since;
        return {
          id,
          slug: a?.slug ?? id,
          displayName: a?.displayName ?? null,
          status: a?.status ?? null,
          quarantined: a?.quarantine?.active ?? false,
          windowStart: windowStart.toISOString(),
          decisions: sum(rows, 'decisions'),
          allowed: sum(rows, 'allowed'),
          denied: sum(rows, 'denied'),
          stopped: sum(rows, 'stopped'),
          approvalRequired: sum(rows, 'approvalRequired'),
          mutating: rows
            .filter((r) => r.mutating)
            .reduce((n, r) => n + r.decisions, 0),
          destructive: rows
            .filter((r) => r.destructive)
            .reduce((n, r) => n + r.decisions, 0),
          distinctMutatingTargets:
            targets.find((t) => t.agentId === id)?.n ?? 0,
          firstSeenAt: new Date(
            Math.min(...rows.map((r) => r.firstSeenAt.getTime())),
          ).toISOString(),
          lastSeenAt: new Date(lastActive.get(id) ?? 0).toISOString(),
          baselineDecisions24h:
            baseline.find((b) => b.agentId === id)?._count._all ?? 0,
          approvals: byStatus(approvals, id),
          invocations: byStatus(invocations, id),
          actions: rows.map((r) => ({
            toolId: r.toolId,
            actionId: r.actionId,
            decisions: r.decisions,
            denied: r.denied,
            stopped: r.stopped,
            mutating: r.mutating,
            destructive: r.destructive,
            distinctResources: r.distinctResources,
            firstSeenAt: r.firstSeenAt.toISOString(),
            lastSeenAt: r.lastSeenAt.toISOString(),
            firstEverAt: r.firstEverAt.toISOString(),
          })),
          evidence: evidence.filter((e) => e.agentId === id).map((e) => e.id),
        };
      }),
      baselineWindowSeconds: BASELINE_WINDOW_MS / 1000,
    };
  }
}
