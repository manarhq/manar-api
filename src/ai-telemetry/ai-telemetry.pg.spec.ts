import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ControlPrismaService } from '../database/control-prisma.service';
import { AI_PRICE_TABLE } from './ai-prices';
import { AiTelemetryService, type AiCall } from './ai-telemetry.service';

/** Real Postgres (the unit job's control DB with migrations applied); skipped without it. */
const url = process.env.CONTROL_DATABASE_URL;

describe.skipIf(!url)('AiTelemetryService (postgres)', () => {
  const control = new ControlPrismaService({ get: () => url } as never);
  const telemetry = new AiTelemetryService(control);
  const a = `ai-${randomUUID()}`;
  const b = `ai-${randomUUID()}`;
  const call = (tenantId: string, extra: Partial<AiCall> = {}): AiCall => ({
    tenantId,
    feature: 'assistant',
    provider: 'azure_openai',
    model: 'gpt-5-mini',
    inputTokens: 1000,
    outputTokens: 200,
    latencyMs: 900,
    outcome: 'ok',
    ...extra,
  });
  const now = new Date('2026-11-05T10:00:00Z');

  beforeAll(() => control.$connect());
  afterAll(async () => {
    await control.aiUsageDaily.deleteMany({
      where: { tenantId: { in: [a, b] } },
    });
    await control.$disconnect();
  });

  it('adds every call to one daily row: tokens, cost from the price table, errors, latency buckets', async () => {
    await telemetry.record(call(a), now);
    await telemetry.record(
      call(a, {
        latencyMs: 30_000,
        outcome: 'error',
        inputTokens: 500,
        outputTokens: 0,
      }),
      now,
    );
    await telemetry.record(call(a, { outcome: 'cancelled' }), now);

    const rows = await control.aiUsageDaily.findMany({
      where: { tenantId: a },
    });
    expect(rows).toHaveLength(1);
    const r = rows[0]!;
    expect(r.calls).toBe(3);
    expect(r.errors).toBe(1);
    expect(Number(r.inputTokens)).toBe(2500);
    expect(Number(r.outputTokens)).toBe(400);
    // (1000+500+1000) in at 0.25 + (200+0+200) out at 2.0 micro-dollars per token
    expect(Number(r.costMicros)).toBe(2500 * 0.25 + 400 * 2);
    expect(r.priceVersion).toBe(AI_PRICE_TABLE.version);
    expect(r.latencyBuckets.reduce((x, y) => x + y, 0)).toBe(3);
    expect(r.latencyBuckets[2]).toBe(2); // 900 ms is in the 500-1000 ms bucket
    expect(r.unpricedCalls).toBe(0);
  });

  it('keeps workspaces, features and models apart, and counts an unknown model as unpriced', async () => {
    await telemetry.record(call(b, { feature: 'incident_summary' }), now);
    await telemetry.record(call(b, { model: 'mystery-9' }), now);
    const rows = await control.aiUsageDaily.findMany({
      where: { tenantId: b },
    });
    expect(rows).toHaveLength(2);
    const unknown = rows.find((r) => r.model === 'mystery-9')!;
    expect(unknown.unpricedCalls).toBe(1);
    expect(Number(unknown.costMicros)).toBe(0);
  });

  it('summarises by workspace with p50/p95, error rate and cost, and ranks the costliest first', async () => {
    const rows = await telemetry.summary({
      from: now,
      to: now,
      groupBy: ['workspace'],
      tenantId: a,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ workspaceId: a, calls: 3, errors: 1 });
    expect(rows[0]!.errorRate).toBeCloseTo(1 / 3);
    expect(rows[0]!.costUsd).toBeCloseTo((2500 * 0.25 + 400 * 2) / 1e6);
    expect(rows[0]!.p95Ms).toBeGreaterThan(rows[0]!.p50Ms);

    const top = await telemetry.topWorkspaces(now, 100);
    const ours = top.filter((r) => r.workspaceId === a || r.workspaceId === b);
    expect(ours[0]!.workspaceId).toBe(a);
  });

  it('flags today against the workspace median of the days before', async () => {
    const t = `ai-${randomUUID()}`;
    for (const d of [1, 2, 3]) {
      await telemetry.record(
        call(t, { inputTokens: 4_000_000, outputTokens: 1_000_000 }), // 3 USD
        new Date(now.getTime() - d * 86_400_000),
      );
    }
    for (let i = 0; i < 4; i++)
      await telemetry.record(
        call(t, { inputTokens: 4_000_000, outputTokens: 1_000_000 }),
        now,
      );
    try {
      const spikes = await telemetry.spikes(now);
      const mine = spikes.find((s) => s.tenantId === t);
      expect(mine).toMatchObject({ todayUsd: 12, baselineUsd: 3 });
    } finally {
      await control.aiUsageDaily.deleteMany({ where: { tenantId: t } });
    }
  });
});
