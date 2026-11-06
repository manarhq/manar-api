import { Injectable, Logger } from '@nestjs/common';
import { ControlPrismaService } from '../database/control-prisma.service';
import { recordAiCall } from '../metrics/metrics';
import { AI_PRICE_TABLE, costMicros } from './ai-prices';
import {
  AI_LATENCY_BUCKET_COUNT,
  addBuckets,
  latencyBucket,
  percentileMs,
} from './ai-latency';
import { detectSpikes, SPIKE_DEFAULTS, type SpendSpike } from './ai-spike';

export const AI_FEATURES = [
  'assistant',
  'incident_summary',
  'audit_investigate',
  'policy_suggest',
] as const;
export type AiFeature = (typeof AI_FEATURES)[number];

/** `ok`: answered. `unavailable`: no model answered (down, circuit open, residency block). `error`: failed. `cancelled`: the user stopped it. */
export type AiOutcome = 'ok' | 'unavailable' | 'error' | 'cancelled';

export interface AiCall {
  tenantId: string;
  feature: AiFeature;
  provider: string;
  model: string;
  inputTokens: number;
  outputTokens: number;
  latencyMs: number;
  /** Request to first streamed token, when the call streamed. */
  firstTokenMs?: number;
  outcome: AiOutcome;
}

export type GroupKey = 'workspace' | 'feature' | 'model' | 'day';

export interface UsageRow {
  workspaceId?: string;
  workspaceName?: string | null;
  feature?: string;
  model?: string;
  day?: string;
  calls: number;
  errors: number;
  errorRate: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  unpricedCalls: number;
  p50Ms: number;
  p95Ms: number;
}

const utcDay = (d: Date): Date =>
  new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
const dayString = (d: Date): string => d.toISOString().slice(0, 10);
const num = (v: bigint | number): number => Number(v);

/**
 * Per-call cost telemetry (performance program, decision 9). Each model call adds one row-update
 * to its daily rollup (workspace, feature, provider, model) and to the Prometheus totals (feature
 * and model only: no workspace label). It never stores or logs a prompt, an answer or a person,
 * and it never fails the call it measures.
 */
@Injectable()
export class AiTelemetryService {
  private readonly logger = new Logger(AiTelemetryService.name);

  constructor(private readonly control: ControlPrismaService) {}

  async record(call: AiCall, now = new Date()): Promise<void> {
    const cost = costMicros(
      call.provider,
      call.model,
      call.inputTokens,
      call.outputTokens,
    );
    recordAiCall({
      feature: call.feature,
      model: call.model,
      outcome: call.outcome,
      inputTokens: call.inputTokens,
      outputTokens: call.outputTokens,
      seconds: call.latencyMs / 1000,
      firstTokenSeconds:
        call.firstTokenMs === undefined ? undefined : call.firstTokenMs / 1000,
      costUsd: cost.micros / 1_000_000,
    });
    const bucket = latencyBucket(call.latencyMs);
    const counts = new Array<number>(AI_LATENCY_BUCKET_COUNT).fill(0);
    counts[bucket] = 1;
    const errors =
      call.outcome === 'ok' || call.outcome === 'cancelled' ? 0 : 1;
    const unpriced = cost.priced ? 0 : 1;
    const day = utcDay(now);
    try {
      await this.control.$executeRaw`
        INSERT INTO "ai_usage_daily" AS t
          ("day", "tenantId", "feature", "provider", "model", "calls", "errors",
           "inputTokens", "outputTokens", "costMicros", "unpricedCalls", "latencyMsSum",
           "latencyBuckets", "priceVersion", "updatedAt")
        VALUES (${day}::date, ${call.tenantId}, ${call.feature}, ${call.provider}, ${call.model},
                1, ${errors}, ${call.inputTokens}, ${call.outputTokens}, ${cost.micros},
                ${unpriced}, ${Math.round(call.latencyMs)}, ${counts}::int[],
                ${AI_PRICE_TABLE.version}, now())
        ON CONFLICT ("day", "tenantId", "feature", "provider", "model") DO UPDATE SET
          "calls" = t."calls" + 1,
          "errors" = t."errors" + ${errors},
          "inputTokens" = t."inputTokens" + ${call.inputTokens},
          "outputTokens" = t."outputTokens" + ${call.outputTokens},
          "costMicros" = t."costMicros" + ${cost.micros},
          "unpricedCalls" = t."unpricedCalls" + ${unpriced},
          "latencyMsSum" = t."latencyMsSum" + ${Math.round(call.latencyMs)},
          "latencyBuckets"[${bucket + 1}] = COALESCE(t."latencyBuckets"[${bucket + 1}], 0) + 1,
          "priceVersion" = ${AI_PRICE_TABLE.version},
          "updatedAt" = now()`;
    } catch (error) {
      // Telemetry must never fail or slow the answer; the Prometheus totals above still counted.
      this.logger.warn(
        `AI usage rollup failed (feature ${call.feature}): ${error instanceof Error ? error.name : 'error'}`,
      );
    }
  }

  /** Usage grouped by any of workspace, feature, model, day, between two UTC dates (inclusive). */
  async summary(input: {
    from: Date;
    to: Date;
    groupBy: GroupKey[];
    tenantId?: string;
    feature?: string;
    model?: string;
  }): Promise<UsageRow[]> {
    const rows = await this.control.aiUsageDaily.findMany({
      where: {
        day: { gte: utcDay(input.from), lte: utcDay(input.to) },
        ...(input.tenantId ? { tenantId: input.tenantId } : {}),
        ...(input.feature ? { feature: input.feature } : {}),
        ...(input.model ? { model: input.model } : {}),
      },
    });
    type Acc = UsageRow & { buckets: number[]; costMicros: number };
    const groups = new Map<string, Acc>();
    for (const r of rows) {
      const key: Partial<UsageRow> = {};
      if (input.groupBy.includes('workspace')) key.workspaceId = r.tenantId;
      if (input.groupBy.includes('feature')) key.feature = r.feature;
      if (input.groupBy.includes('model')) key.model = r.model;
      if (input.groupBy.includes('day')) key.day = dayString(r.day);
      const id = JSON.stringify(key);
      let g = groups.get(id);
      if (!g) {
        g = {
          ...key,
          calls: 0,
          errors: 0,
          errorRate: 0,
          inputTokens: 0,
          outputTokens: 0,
          costUsd: 0,
          unpricedCalls: 0,
          p50Ms: 0,
          p95Ms: 0,
          buckets: new Array<number>(AI_LATENCY_BUCKET_COUNT).fill(0),
          costMicros: 0,
        };
        groups.set(id, g);
      }
      g.calls += r.calls;
      g.errors += r.errors;
      g.inputTokens += num(r.inputTokens);
      g.outputTokens += num(r.outputTokens);
      g.costMicros += num(r.costMicros);
      g.unpricedCalls += r.unpricedCalls;
      addBuckets(g.buckets, r.latencyBuckets);
    }
    const out: UsageRow[] = [];
    for (const g of groups.values()) {
      const { buckets, costMicros: micros, ...row } = g;
      out.push({
        ...row,
        costUsd: micros / 1_000_000,
        errorRate: g.calls ? g.errors / g.calls : 0,
        p50Ms: percentileMs(buckets, 0.5),
        p95Ms: percentileMs(buckets, 0.95),
      });
    }
    out.sort((a, b) => b.costUsd - a.costUsd || b.calls - a.calls);
    return input.groupBy.includes('workspace') ? this.withNames(out) : out;
  }

  /** The `limit` workspaces that cost the most on one UTC day (today by default). */
  async topWorkspaces(day = new Date(), limit = 10): Promise<UsageRow[]> {
    const rows = await this.summary({
      from: day,
      to: day,
      groupBy: ['workspace'],
    });
    return rows.slice(0, limit);
  }

  /**
   * Today's spend against each workspace's own median of the last days, and the platform total
   * against its own: the signal Desk turns into an alert (decision 7).
   */
  async spikes(
    now = new Date(),
    options: Partial<typeof SPIKE_DEFAULTS> = {},
  ): Promise<SpendSpike[]> {
    const lookback = options.lookbackDays ?? SPIKE_DEFAULTS.lookbackDays;
    const today = utcDay(now);
    const from = new Date(today.getTime() - lookback * 86_400_000);
    const rows = await this.control.aiUsageDaily.findMany({
      where: { day: { gte: from, lte: today } },
      select: { day: true, tenantId: true, costMicros: true },
    });
    const perTenantDay = new Map<string, Map<string | null, number>>();
    const add = (day: string, key: string | null, usd: number): void => {
      const byKey = perTenantDay.get(day) ?? new Map<string | null, number>();
      byKey.set(key, (byKey.get(key) ?? 0) + usd);
      perTenantDay.set(day, byKey);
    };
    for (const r of rows) {
      const usd = num(r.costMicros) / 1_000_000;
      add(dayString(r.day), r.tenantId, usd);
      add(dayString(r.day), null, usd);
    }
    const todayKeys =
      perTenantDay.get(dayString(today)) ?? new Map<string | null, number>();
    const history = new Map<string | null, number[]>();
    for (const [day, byKey] of perTenantDay) {
      if (day === dayString(today)) continue;
      for (const [key, usd] of byKey) {
        history.set(key, [...(history.get(key) ?? []), usd]);
      }
    }
    return detectSpikes(todayKeys, history, options);
  }

  private async withNames(rows: UsageRow[]): Promise<UsageRow[]> {
    const ids = [...new Set(rows.map((r) => r.workspaceId).filter(Boolean))];
    if (ids.length === 0) return rows;
    const tenants = await this.control.tenant.findMany({
      where: { id: { in: ids as string[] } },
      select: { id: true, name: true },
    });
    const names = new Map(tenants.map((t) => [t.id, t.name]));
    return rows.map((r) => ({
      ...r,
      workspaceName: names.get(r.workspaceId ?? '') ?? null,
    }));
  }
}
