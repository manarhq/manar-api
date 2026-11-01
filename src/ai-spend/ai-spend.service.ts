import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
} from '@nestjs/common';
import { z } from 'zod';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditActor } from '../audit/audit-event-types';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { KNOWN_HOST_TOOL_IDS } from '../tools/host-actions';
import { costMicros, isPriced } from './pricing';

type Client = Awaited<ReturnType<TenantDatabaseManager['getClient']>>;

/** DOOR cannot tell which tool made a call when the User-Agent is unknown: one fixed bucket. */
export const UNATTRIBUTED_TOOL = 'other:unknown';
const toolId = z
  .string()
  .refine(
    (id) => id === UNATTRIBUTED_TOOL || KNOWN_HOST_TOOL_IDS.includes(id),
    {
      message: 'unknown tool',
    },
  );

/**
 * Bounds on one report. DOOR sends one every minute (more only after the API was unreachable), so
 * these are generous for a real heavy day and small next to what a tampered device would claim.
 */
export const BOUNDS = {
  records: 100,
  guard: 50,
  /** About ten times what a very busy device sends in a minute (cache reads included). */
  requestsPerMinute: 600,
  inputPerMinute: 10_000_000,
  outputPerMinute: 1_000_000,
  /** A batch may cover the time since the device's last accepted one (it keeps counting while offline), up to a day. */
  maxMinutes: 1440,
  firstReportMinutes: 60,
  /** Reports per host: DOOR sends about one a minute. */
  reportsPerWindow: 10,
  windowMs: 10 * 60_000,
  /** A device whose day spend passes this, and 5x the median of the others, raises an alert. */
  outlierFloorMicros: 25_000_000n,
  outlierAloneMicros: 100_000_000n,
} as const;

/** `POST /host/v1/ai-usage`: what DOOR counted since its last report, and the secrets it handled. */
export const AiUsageBatchSchema = z.object({
  /** Made by the device for each batch; a repeat is ignored, so a replay cannot inflate totals. */
  batchId: z.string().regex(/^[a-f0-9]{32}$/),
  /** Requests DOOR turned away because the body could not be checked. */
  refused: z.number().int().min(0).max(1_000_000).default(0),
  usage: z.array(
    z.object({
      toolId,
      /** The local user DOOR named (`uid:1000`, `sid:S-1-5-...`). */
      localUser: z.string().regex(/^(uid:\d{1,10}|sid:S-[0-9-]{1,100})$/),
      provider: z.enum(['anthropic', 'openai', 'gemini']),
      model: z.string().regex(/^[A-Za-z0-9._:/-]{1,100}$/),
      requests: z.number().int().min(0),
      inputTokens: z.number().int().min(0),
      outputTokens: z.number().int().min(0),
    }),
  ),
  guard: z.array(
    z.object({
      toolId,
      kind: z.string().regex(/^[a-z0-9_]{1,40}$/),
      action: z.enum(['masked', 'blocked']),
      count: z.number().int().min(1).max(1_000_000),
      // First characters of the secret then ****, as DOOR masks it. Anything else is refused.
      sample: z.string().regex(/^[\x21-\x7e]{0,4}\*{4}$/),
    }),
  ),
});
export type AiUsageBatch = z.infer<typeof AiUsageBatchSchema>;

/** The first out-of-bound reason in a parsed batch, or null. `minutes` is the time it may cover. */
export function boundsProblem(b: AiUsageBatch, minutes: number): string | null {
  if (b.usage.length > BOUNDS.records) return 'too many usage records';
  if (b.guard.length > BOUNDS.guard) return 'too many guard records';
  const m = Math.min(Math.max(minutes, 1), BOUNDS.maxMinutes);
  let req = 0;
  let inp = 0;
  let out = 0;
  for (const u of b.usage) {
    req += u.requests;
    inp += u.inputTokens;
    out += u.outputTokens;
  }
  if (req > BOUNDS.requestsPerMinute * m) return 'requests out of bounds';
  if (inp > BOUNDS.inputPerMinute * m) return 'input tokens out of bounds';
  if (out > BOUNDS.outputPerMinute * m) return 'output tokens out of bounds';
  return null;
}

export const AiSpendSettingsSchema = z.object({
  monthlyBudgetUsd: z.number().min(0).max(1_000_000).nullable(),
  monthlyCapUsd: z.number().min(0).max(1_000_000).nullable(),
  secretsMode: z.enum(['mask', 'block']),
  capScope: z.enum(['owner', 'workspace']),
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
  return { totalUsd: out.reduce((s, r) => s + r.costUsd, 0), rows: out };
}

/** Month spend of one provider inside one cap scope, with each device's part. A cap is by provider, not by tool name: the name a caller gives is not trusted. */
type ToolSpend = { total: bigint; hosts: Map<string, bigint> };
type Scope = 'owner' | 'workspace';
type HostRef = {
  hostId: string;
  tenantId: string;
  ownerSubject: string | null;
};

@Injectable()
export class AiSpendService {
  private readonly logger = new Logger(AiSpendService.name);
  // ponytail: per API replica; move to Redis if the API runs more than one replica and this matters.
  private readonly reports = new Map<string, number[]>();

  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly audit: AuditService,
  ) {}

  private settingsOf(client: Client) {
    return client.aiSpendSettings.findUnique({ where: { id: 'default' } });
  }

  /** Device ids whose spend counts together with `host`'s: its owner's devices, or everyone's. */
  private async scopeHosts(
    client: Client,
    host: HostRef,
    scope: Scope,
  ): Promise<string[] | null> {
    if (scope === 'workspace') return null;
    if (!host.ownerSubject) return [host.hostId]; // no known owner: the device stands alone
    const hs = await client.host.findMany({
      where: { ownerSubject: host.ownerSubject },
      select: { id: true },
    });
    return hs.map((h) => h.id);
  }

  private async monthByProvider(
    client: Client,
    now: Date,
    hostIds: string[] | null,
  ): Promise<Map<string, ToolSpend>> {
    const rows = await client.aiUsageDaily.groupBy({
      by: ['provider', 'hostId'],
      where: {
        day: { gte: periodStarts(now).month },
        ...(hostIds ? { hostId: { in: hostIds } } : {}),
      },
      _sum: { costMicros: true },
    });
    const out = new Map<string, ToolSpend>();
    for (const r of rows) {
      const v = r._sum.costMicros ?? 0n;
      const t = out.get(r.provider) ?? { total: 0n, hosts: new Map() };
      t.total += v;
      t.hosts.set(r.hostId, v);
      out.set(r.provider, t);
    }
    return out;
  }

  private limited(hostId: string, nowMs: number): boolean {
    const recent = (this.reports.get(hostId) ?? []).filter(
      (t) => nowMs - t < BOUNDS.windowMs,
    );
    if (recent.length >= BOUNDS.reportsPerWindow) {
      this.reports.set(hostId, recent);
      return true;
    }
    recent.push(nowMs);
    this.reports.set(hostId, recent);
    return false;
  }

  /**
   * `POST /host/v1/ai-usage`: checks, then stores. A report over the rate limit gets 429; one that
   * fails the schema or the bounds gets 400 and an audit event (reason only, never the payload),
   * and nothing is applied.
   */
  async submit(host: HostRef, body: unknown, now = new Date()) {
    if (this.limited(host.hostId, now.getTime()))
      throw new HttpException(
        'too many usage reports',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    const parsed = AiUsageBatchSchema.safeParse(body);
    let problem: string | null;
    if (parsed.success) {
      // How long this report may cover: since the device's last accepted one.
      const client = await this.tenants.getClient(host.tenantId);
      const last = await client.aiUsageBatch.findFirst({
        where: { hostId: host.hostId },
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      });
      const minutes = last
        ? (now.getTime() - last.createdAt.getTime()) / 60_000
        : BOUNDS.firstReportMinutes;
      problem = boundsProblem(parsed.data, minutes);
    } else {
      problem = parsed.error.issues
        .slice(0, 3)
        .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
        .join('; ');
    }
    if (!parsed.success || problem) {
      const client = await this.tenants.getClient(host.tenantId);
      await this.audit.recordSafely(client, host.tenantId, {
        eventType: AUDIT_EVENT_TYPES.DOOR_USAGE_REJECTED,
        actor: { type: 'system', id: `host:${host.hostId}` },
        data: { hostId: host.hostId, reason: (problem ?? '').slice(0, 300) },
      });
      throw new BadRequestException(`Invalid usage report: ${problem}`);
    }
    return this.ingest(host, parsed.data, now);
  }

  async ingest(
    host: HostRef,
    input: AiUsageBatch,
    now = new Date(),
  ): Promise<{ accepted: boolean }> {
    const client = await this.tenants.getClient(host.tenantId);
    const settings = await this.settingsOf(client);
    const scope: Scope =
      settings?.capScope === 'workspace' ? 'workspace' : 'owner';
    const scopeIds = await this.scopeHosts(client, host, scope);
    const before = await this.monthByProvider(client, now, scopeIds);
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
      await tx.aiUsageBatch.deleteMany({
        where: {
          hostId: host.hostId,
          createdAt: { lt: new Date(now.getTime() - 30 * 86_400_000) },
        },
      });
      for (const u of input.usage) {
        const cost = BigInt(costMicros(u.model, u.inputTokens, u.outputTokens));
        await tx.aiUsageDaily.upsert({
          where: {
            hostId_day_toolId_localUser_provider_model: {
              hostId: host.hostId,
              day,
              toolId: u.toolId,
              localUser: u.localUser,
              provider: u.provider,
              model: u.model,
            },
          },
          create: {
            hostId: host.hostId,
            day,
            toolId: u.toolId,
            localUser: u.localUser,
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
    if (input.refused > 0) {
      await this.audit.recordSafely(client, host.tenantId, {
        eventType: AUDIT_EVENT_TYPES.DOOR_REQUEST_REFUSED,
        actor,
        data: {
          hostId: host.hostId,
          count: input.refused,
          reason: 'unsupported_encoding',
        },
      });
    }
    if (input.usage.length > 0) await this.outlier(client, host, actor, now);
    // Alert once, when this batch takes the month over the budget or a provider over its cap.
    if (input.usage.length > 0) {
      const after = await this.monthByProvider(client, now, scopeIds);
      const budget = settings?.monthlyBudgetMicros;
      if (budget != null && budget > 0n) {
        // The budget is an alert on the whole workspace, whoever spent it.
        const ws = await this.monthByProvider(client, now, null);
        const totalAfter = [...ws.values()].reduce((a, v) => a + v.total, 0n);
        const batchCost = input.usage.reduce(
          (a, u) =>
            a + BigInt(costMicros(u.model, u.inputTokens, u.outputTokens)),
          0n,
        );
        if (totalAfter - batchCost < budget && totalAfter >= budget) {
          await this.limitEvent(
            client,
            host,
            actor,
            'budget',
            null,
            totalAfter,
            budget,
            'workspace',
            [],
          );
        }
      }
      const cap = settings?.monthlyCapMicros;
      if (cap != null && cap > 0n) {
        for (const [provider, v] of after) {
          if ((before.get(provider)?.total ?? 0n) < cap && v.total >= cap) {
            const contributors = [...v.hosts].map(([hostId, m]) => ({
              hostId,
              usd: toUsd(m),
            }));
            await this.limitEvent(
              client,
              host,
              actor,
              'cap',
              provider,
              v.total,
              cap,
              scope,
              contributors,
            );
          }
        }
      }
    }
    return { accepted: true };
  }

  private readonly outliers = new Set<string>();

  /** Alerts once a day when one device's spend is far above the workspace's other devices. */
  private async outlier(
    client: Client,
    host: HostRef,
    actor: AuditActor,
    now: Date,
  ) {
    const day = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()),
    );
    const key = `${host.tenantId}|${host.hostId}|${day.toISOString()}`;
    if (this.outliers.has(key)) return;
    const rows = await client.aiUsageDaily.groupBy({
      by: ['hostId'],
      where: { day },
      _sum: { costMicros: true },
    });
    const mine =
      rows.find((r) => r.hostId === host.hostId)?._sum.costMicros ?? 0n;
    const others = rows
      .filter((r) => r.hostId !== host.hostId)
      .map((r) => r._sum.costMicros ?? 0n)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const median =
      others.length >= 3 ? others[Math.floor(others.length / 2)]! : 0n;
    const threshold =
      others.length >= 3
        ? 5n * median > BOUNDS.outlierFloorMicros
          ? 5n * median
          : BOUNDS.outlierFloorMicros
        : BOUNDS.outlierAloneMicros;
    if (mine < threshold) return;
    this.outliers.add(key);
    await this.audit.recordSafely(client, host.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SPEND_HOST_OUTLIER,
      actor,
      data: {
        hostId: host.hostId,
        todayUsd: toUsd(mine),
        thresholdUsd: toUsd(threshold),
      },
    });
  }

  private limitEvent(
    client: Client,
    host: HostRef,
    actor: AuditActor,
    limit: 'budget' | 'cap',
    provider: string | null,
    spent: bigint,
    max: bigint,
    scope: Scope,
    contributors: Array<{ hostId: string; usd: number | null }>,
  ) {
    return this.audit.recordSafely(client, host.tenantId, {
      eventType: AUDIT_EVENT_TYPES.AI_SPEND_LIMIT_REACHED,
      actor,
      data: {
        limit,
        provider,
        scope,
        spentUsd: toUsd(spent),
        limitUsd: toUsd(max),
        contributors,
      },
    });
  }

  /**
   * The "door" part of `GET /host/v1/config`: secrets mode and the providers the monthly cap paused
   * for this device. By default a cap counts one owner's devices and pauses only those; the
   * workspace scope (an admin choice) counts everyone together. If the spend cannot be read the
   * call fails and the device keeps its last state.
   */
  async doorConfig(
    host: HostRef,
  ): Promise<{ secrets: 'mask' | 'block'; paused: string[] }> {
    const client = await this.tenants.getClient(host.tenantId);
    const s = await this.settingsOf(client);
    const cap = s?.monthlyCapMicros;
    let paused: string[] = [];
    if (cap != null && cap > 0n) {
      const scope: Scope = s?.capScope === 'workspace' ? 'workspace' : 'owner';
      const ids = await this.scopeHosts(client, host, scope);
      const month = await this.monthByProvider(client, new Date(), ids);
      paused = [...month]
        .filter(([, v]) => v.total >= cap)
        .map(([t]) => t)
        .sort();
    }
    return { secrets: s?.secretsMode === 'block' ? 'block' : 'mask', paused };
  }

  /** `GET /ai-spend`. */
  async overview(tenantId: string, now = new Date()) {
    const client = await this.tenants.getClient(tenantId);
    const { week, month } = periodStarts(now);
    const sum = {
      requests: true,
      inputTokens: true,
      outputTokens: true,
      costMicros: true,
    } as const;
    const [rows, weekRows, s, perHost] = await Promise.all([
      client.aiUsageDaily.groupBy({
        by: ['toolId', 'provider', 'model'],
        where: { day: { gte: month } },
        _sum: sum,
      }),
      client.aiUsageDaily.groupBy({
        by: ['toolId', 'provider', 'model'],
        where: { day: { gte: week } },
        _sum: sum,
      }),
      this.settingsOf(client),
      client.aiUsageDaily.groupBy({
        by: ['provider', 'hostId'],
        where: { day: { gte: month } },
        _sum: { costMicros: true },
      }),
    ]);
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
    const cap = s?.monthlyCapMicros;
    const scope: Scope = s?.capScope === 'workspace' ? 'workspace' : 'owner';
    const usedPct = budget && budget > 0 ? (m.totalUsd / budget) * 100 : null;
    // A tool shows as paused when any cap group (one owner's devices, or all) has reached the cap.
    const paused = new Set<string>();
    if (cap != null && cap > 0n) {
      const owners = new Map(
        (
          await client.host.findMany({
            where: { id: { in: [...new Set(perHost.map((r) => r.hostId))] } },
            select: { id: true, ownerSubject: true },
          })
        ).map((h) => [h.id, h.ownerSubject]),
      );
      const groups = new Map<string, bigint>();
      for (const r of perHost) {
        const g =
          scope === 'workspace'
            ? 'all'
            : (owners.get(r.hostId) ?? `host:${r.hostId}`);
        const k = `${r.provider}\u0000${g}`;
        groups.set(k, (groups.get(k) ?? 0n) + (r._sum.costMicros ?? 0n));
      }
      for (const [k, v] of groups)
        if (v >= cap) paused.add(k.split('\u0000')[0]!);
    }
    return {
      estimated: true,
      currency: 'USD',
      week: w,
      month: m,
      settings: {
        monthlyBudgetUsd: budget,
        monthlyCapUsd: toUsd(cap),
        secretsMode: s?.secretsMode === 'block' ? 'block' : 'mask',
        capScope: scope,
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
      paused: [...paused].sort(),
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
      capScope: input.capScope,
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
          capScope: before?.capScope ?? 'owner',
        },
        after: input,
      },
    });
    this.logger.log(`ai spend settings changed for tenant ${tenantId}`);
    return input;
  }
}
