import { Injectable, Logger } from '@nestjs/common';
import { z } from 'zod';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditActor } from '../audit/audit-event-types';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { costMicros, isPriced } from './pricing';

const TOOL_ID = /^(host\.[a-z0-9-]{1,40}|other:[a-z0-9._-]{1,60})$/;
const MAX_TOKENS = 10_000_000_000;

/** `POST /host/v1/ai-usage`: what DOOR counted since its last report, and the secrets it handled. */
export const AiUsageBatchSchema = z.object({
  batchId: z.string().regex(/^[a-f0-9]{32}$/),
  usage: z
    .array(
      z.object({
        toolId: z.string().regex(TOOL_ID),
        provider: z.enum(['anthropic', 'openai', 'gemini']),
        model: z.string().min(1).max(100),
        requests: z.number().int().min(0).max(1_000_000),
        inputTokens: z.number().int().min(0).max(MAX_TOKENS),
        outputTokens: z.number().int().min(0).max(MAX_TOKENS),
      }),
    )
    .max(200),
  guard: z
    .array(
      z.object({
        toolId: z.string().regex(TOOL_ID),
        kind: z.string().regex(/^[a-z0-9_]{1,40}$/),
        action: z.enum(['masked', 'blocked']),
        count: z.number().int().min(1).max(1_000_000),
        // First characters of the secret then ****, as DOOR masks it. Anything else is refused.
        sample: z.string().regex(/^[\x21-\x7e]{0,4}\*{4}$/),
      }),
    )
    .max(100),
});
export type AiUsageBatch = z.infer<typeof AiUsageBatchSchema>;

export const AiSpendSettingsSchema = z.object({
  monthlyBudgetUsd: z.number().min(0).max(1_000_000).nullable(),
  monthlyCapUsd: z.number().min(0).max(1_000_000).nullable(),
  secretsMode: z.enum(['mask', 'block']),
});
export type AiSpendSettingsInput = z.infer<typeof AiSpendSettingsSchema>;

const toUsd = (micros: bigint | number | null | undefined) =>
  micros == null ? null : Number(micros) / 1_000_000;
const toMicros = (usd: number | null) =>
  usd == null ? null : BigInt(Math.round(usd * 1_000_000));

/** First day of the UTC month / 6 days ago (so "this week" is the last 7 days incl. today). */
export function periodStarts(now: Date): { week: Date; month: Date } {
  const day = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
  );
  return {
    week: new Date(day - 6 * 86_400_000),
    month: new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)),
  };
}

type Row = {
  toolId: string;
  provider: string;
  model: string;
  requests: number;
  inputTokens: bigint;
  outputTokens: bigint;
  costMicros: bigint;
};

function summarize(rows: Row[]) {
  const key = (r: Row) => `${r.toolId}|${r.provider}|${r.model}`;
  const m = new Map<string, Row>();
  for (const r of rows) {
    const cur = m.get(key(r));
    m.set(
      key(r),
      cur
        ? {
            ...cur,
            requests: cur.requests + r.requests,
            inputTokens: cur.inputTokens + r.inputTokens,
            outputTokens: cur.outputTokens + r.outputTokens,
            costMicros: cur.costMicros + r.costMicros,
          }
        : r,
    );
  }
  const out = [...m.values()]
    .map((r) => ({
      toolId: r.toolId,
      provider: r.provider,
      model: r.model,
      requests: r.requests,
      inputTokens: Number(r.inputTokens),
      outputTokens: Number(r.outputTokens),
      costUsd: toUsd(r.costMicros) ?? 0,
      priced: isPriced(r.model),
    }))
    .sort((a, b) => b.costUsd - a.costUsd || a.toolId.localeCompare(b.toolId));
  return {
    totalUsd: out.reduce((s, r) => s + r.costUsd, 0),
    rows: out,
  };
}

@Injectable()
export class AiSpendService {
  private readonly logger = new Logger(AiSpendService.name);

  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  private async settingsOf(
    client: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
  ) {
    return client.aiSpendSettings.findUnique({ where: { id: 'default' } });
  }

  /** Month spend per tool across the workspace, in micro-dollars. */
  private async monthByTool(
    client: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    now: Date,
  ): Promise<Map<string, bigint>> {
    const rows = await client.aiUsageDaily.groupBy({
      by: ['toolId'],
      where: { day: { gte: periodStarts(now).month } },
      _sum: { costMicros: true },
    });
    return new Map(rows.map((r) => [r.toolId, r._sum.costMicros ?? 0n]));
  }

  /** `POST /host/v1/ai-usage`. The device is the tenant's own, from its certificate. */
  async ingest(
    host: { hostId: string; tenantId: string },
    input: AiUsageBatch,
    now = new Date(),
  ): Promise<{ accepted: boolean }> {
    const client = await this.tenants.getClient(host.tenantId);
    const settings = await this.settingsOf(client);
    const before = await this.monthByTool(client, now);
    const day = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
    );
    let duplicate = false;
    await client.$transaction(async (tx) => {
      const seen = await tx.aiUsageBatch.createMany({
        data: [{ hostId: host.hostId, batchId: input.batchId }],
        skipDuplicates: true,
      });
      if (seen.count === 0) {
        duplicate = true;
        return;
      }
      for (const u of input.usage) {
        const cost = BigInt(costMicros(u.model, u.inputTokens, u.outputTokens));
        await tx.aiUsageDaily.upsert({
          where: {
            hostId_day_toolId_provider_model: {
              hostId: host.hostId,
              day,
              toolId: u.toolId,
              provider: u.provider,
              model: u.model,
            },
          },
          create: {
            hostId: host.hostId,
            day,
            toolId: u.toolId,
            provider: u.provider,
            model: u.model,
            requests: u.requests,
            inputTokens: BigInt(u.inputTokens),
            outputTokens: BigInt(u.outputTokens),
            costMicros: cost,
          },
          update: {
            requests: { increment: u.requests },
            inputTokens: { increment: BigInt(u.inputTokens) },
            outputTokens: { increment: BigInt(u.outputTokens) },
            costMicros: { increment: cost },
          },
        });
      }
    });
    if (duplicate) return { accepted: false };

    const actor: AuditActor = { type: 'system', id: `host:${host.hostId}` };
    // Masked sample only: the batch schema refuses anything but a few characters and ****.
    for (const g of input.guard) {
      await this.audit.recordSafely(client, host.tenantId, {
        eventType:
          g.action === 'masked'
            ? AUDIT_EVENT_TYPES.DOOR_SECRET_MASKED
            : AUDIT_EVENT_TYPES.DOOR_SECRET_BLOCKED,
        actor,
        data: {
          hostId: host.hostId,
          toolId: g.toolId,
          kind: g.kind,
          count: g.count,
          sample: g.sample,
        },
      });
    }
    // Alert once, when this batch takes the month over the budget or a tool over its cap.
    if (input.usage.length > 0) {
      const after = await this.monthByTool(client, now);
      const sum = (m: Map<string, bigint>) =>
        [...m.values()].reduce((a, b) => a + b, 0n);
      const budget = settings?.monthlyBudgetMicros;
      if (
        budget != null &&
        budget > 0n &&
        sum(before) < budget &&
        sum(after) >= budget
      ) {
        await this.limitEvent(
          client,
          host,
          actor,
          'budget',
          null,
          sum(after),
          budget,
        );
      }
      const cap = settings?.monthlyCapMicros;
      if (cap != null && cap > 0n) {
        for (const [tool, v] of after) {
          if ((before.get(tool) ?? 0n) < cap && v >= cap) {
            await this.limitEvent(client, host, actor, 'cap', tool, v, cap);
          }
        }
      }
    }
    return { accepted: true };
  }

  private limitEvent(
    client: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    host: { hostId: string; tenantId: string },
    actor: AuditActor,
    limit: 'budget' | 'cap',
    toolId: string | null,
    spent: bigint,
    max: bigint,
  ) {
    return this.audit.recordSafely(client, host.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SPEND_LIMIT_REACHED,
      actor,
      data: { limit, toolId, spentUsd: toUsd(spent), limitUsd: toUsd(max) },
    });
  }

  /**
   * The "door" part of `GET /host/v1/config`: secrets mode and the tools the monthly cap paused.
   * Fails closed: if the spend cannot be read the call fails and the device keeps its last state.
   */
  async doorConfig(host: {
    tenantId: string;
  }): Promise<{ secrets: 'mask' | 'block'; paused: string[] }> {
    const client = await this.tenants.getClient(host.tenantId);
    const s = await this.settingsOf(client);
    const cap = s?.monthlyCapMicros;
    let paused: string[] = [];
    if (cap != null && cap > 0n) {
      const month = await this.monthByTool(client, new Date());
      paused = [...month]
        .filter(([, v]) => v >= cap)
        .map(([t]) => t)
        .sort();
    }
    return { secrets: s?.secretsMode === 'block' ? 'block' : 'mask', paused };
  }

  /** `GET /ai-spend`. */
  async overview(tenantId: string, now = new Date()) {
    const client = await this.tenants.getClient(tenantId);
    const { week, month } = periodStarts(now);
    const [rows, s] = await Promise.all([
      client.aiUsageDaily.groupBy({
        by: ['toolId', 'provider', 'model'],
        where: { day: { gte: month } },
        _sum: {
          requests: true,
          inputTokens: true,
          outputTokens: true,
          costMicros: true,
        },
      }),
      this.settingsOf(client),
    ]);
    const weekRows = await client.aiUsageDaily.groupBy({
      by: ['toolId', 'provider', 'model'],
      where: { day: { gte: week } },
      _sum: {
        requests: true,
        inputTokens: true,
        outputTokens: true,
        costMicros: true,
      },
    });
    const norm = (r: (typeof rows)[number]): Row => ({
      toolId: r.toolId,
      provider: r.provider,
      model: r.model,
      requests: r._sum.requests ?? 0,
      inputTokens: r._sum.inputTokens ?? 0n,
      outputTokens: r._sum.outputTokens ?? 0n,
      costMicros: r._sum.costMicros ?? 0n,
    });
    const m = summarize(rows.map(norm));
    const w = summarize(weekRows.map(norm));
    const budget = toUsd(s?.monthlyBudgetMicros);
    const cap = toUsd(s?.monthlyCapMicros);
    const usedPct = budget && budget > 0 ? (m.totalUsd / budget) * 100 : null;
    const byTool = new Map<string, number>();
    for (const r of m.rows)
      byTool.set(r.toolId, (byTool.get(r.toolId) ?? 0) + r.costUsd);
    return {
      estimated: true,
      currency: 'USD',
      week: w,
      month: m,
      settings: {
        monthlyBudgetUsd: budget,
        monthlyCapUsd: cap,
        secretsMode: s?.secretsMode === 'block' ? 'block' : 'mask',
      },
      budget: {
        usedPct,
        state:
          usedPct == null
            ? 'none'
            : usedPct >= 100
              ? 'over'
              : usedPct >= 80
                ? 'warning'
                : 'ok',
      },
      paused:
        cap != null && cap > 0
          ? [...byTool]
              .filter(([, v]) => v >= cap)
              .map(([t]) => t)
              .sort()
          : [],
    };
  }

  /** `PUT /ai-spend/settings`. */
  async updateSettings(
    tenantId: string,
    input: AiSpendSettingsInput,
    actor: AuditActor,
  ) {
    const client = await this.tenants.getClient(tenantId);
    const before = await this.settingsOf(client);
    const data = {
      monthlyBudgetMicros: toMicros(input.monthlyBudgetUsd),
      monthlyCapMicros: toMicros(input.monthlyCapUsd),
      secretsMode: input.secretsMode,
      updatedBy: actor.id,
    };
    await client.aiSpendSettings.upsert({
      where: { id: 'default' },
      create: { id: 'default', ...data },
      update: data,
    });
    await this.audit.recordSafely(client, tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SPEND_SETTINGS_CHANGED,
      actor,
      data: {
        before: {
          monthlyBudgetUsd: toUsd(before?.monthlyBudgetMicros),
          monthlyCapUsd: toUsd(before?.monthlyCapMicros),
          secretsMode: before?.secretsMode ?? 'mask',
        },
        after: input,
      },
    });
    this.logger.log(`ai spend settings changed for tenant ${tenantId}`);
    return input;
  }
}
