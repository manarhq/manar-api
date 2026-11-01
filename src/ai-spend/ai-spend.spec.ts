import { describe, expect, it, vi } from 'vitest';
import {
  AiSpendService,
  AiUsageBatchSchema,
  type AiUsageBatch,
} from './ai-spend.service';
import { costMicros, isPriced } from './pricing';

type Usage = Record<string, unknown> & {
  toolId: string;
  costMicros: bigint;
};

function fake(settings: Record<string, unknown> | null = null) {
  const rowsOf = new Map<string, Usage[]>();
  const batches = new Set<string>();
  const clients = new Map<string, unknown>();
  const audit = { recordSafely: vi.fn(() => Promise.resolve({})) };
  const build = (id: string) => {
    const rows: Usage[] = [];
    rowsOf.set(id, rows);
    const tx = {
      aiUsageBatch: {
        createMany: ({
          data,
        }: {
          data: Array<{ hostId: string; batchId: string }>;
        }) => {
          const k = `${data[0]!.hostId}|${data[0]!.batchId}`;
          if (batches.has(k)) return Promise.resolve({ count: 0 });
          batches.add(k);
          return Promise.resolve({ count: 1 });
        },
      },
      aiUsageDaily: {
        upsert: ({ create }: { create: Usage }) => {
          rows.push(create);
          return Promise.resolve({});
        },
        groupBy: () => {
          const by = new Map<string, bigint>();
          for (const r of rows)
            by.set(r.toolId, (by.get(r.toolId) ?? 0n) + r.costMicros);
          return Promise.resolve(
            [...by].map(([toolId, v]) => ({ toolId, _sum: { costMicros: v } })),
          );
        },
      },
      aiSpendSettings: { findUnique: () => Promise.resolve(settings) },
      $transaction: (fn: (t: unknown) => Promise<void>) => fn(tx),
    };
    return tx;
  };
  const tenants = {
    getClient: vi.fn((id: string) => {
      if (!clients.has(id)) clients.set(id, build(id));
      return Promise.resolve(clients.get(id));
    }),
  };
  return {
    get rows() {
      return rowsOf.get('t1') ?? [];
    },
    audit,
    tenants,
    svc: new AiSpendService(tenants as never, audit as never),
  };
}

const batch = (over: Partial<AiUsageBatch> = {}): AiUsageBatch => ({
  batchId: 'a'.repeat(32),
  usage: [
    {
      toolId: 'host.codex-cli',
      provider: 'openai',
      model: 'gpt-5',
      requests: 2,
      inputTokens: 1_000_000,
      outputTokens: 100_000,
    },
  ],
  guard: [],
  ...over,
});
const host = { hostId: 'h1', tenantId: 't1' };

describe('pricing', () => {
  it('prices by longest prefix and leaves unknown models at zero', () => {
    expect(costMicros('gpt-5', 1_000_000, 100_000)).toBe(2_250_000);
    expect(costMicros('gpt-5-mini-2026', 1_000_000, 0)).toBe(250_000);
    expect(isPriced('mystery-model')).toBe(false);
    expect(costMicros('mystery-model', 5, 5)).toBe(0);
  });
});

describe('batch schema', () => {
  it('refuses a guard sample that is not a masked fragment', () => {
    const bad = batch({
      guard: [
        {
          toolId: 'host.codex-cli',
          kind: 'aws_access_key',
          action: 'masked',
          count: 1,
          sample: 'AKIAIOSFODNN7EXAMPLE',
        },
      ],
    });
    expect(AiUsageBatchSchema.safeParse(bad).success).toBe(false);
    const ok = batch({
      guard: [
        {
          toolId: 'host.codex-cli',
          kind: 'aws_access_key',
          action: 'masked',
          count: 1,
          sample: 'AKIA****',
        },
      ],
    });
    expect(AiUsageBatchSchema.safeParse(ok).success).toBe(true);
  });
});

describe('ingest', () => {
  it('stores usage once per batch id and audits masked samples only', async () => {
    const f = fake();
    const b = batch({
      guard: [
        {
          toolId: 'host.codex-cli',
          kind: 'aws_access_key',
          action: 'blocked',
          count: 3,
          sample: 'AKIA****',
        },
      ],
    });
    expect((await f.svc.ingest(host, b)).accepted).toBe(true);
    expect((await f.svc.ingest(host, b)).accepted).toBe(false); // resend after a lost reply
    expect(f.rows).toHaveLength(1);
    expect(f.rows[0]!.costMicros).toBe(2_250_000n);
    const calls = f.audit.recordSafely.mock.calls as unknown as Array<
      [unknown, string, { eventType: string; data: Record<string, unknown> }]
    >;
    expect(calls).toHaveLength(1);
    expect(calls[0]![2].eventType).toBe('door.secret.blocked');
    expect(calls[0]![2].data).toMatchObject({ sample: 'AKIA****', count: 3 });
  });

  it('records a limit event once when a tool crosses its cap, and pauses it in config', async () => {
    const f = fake({
      monthlyCapMicros: 2_000_000n,
      monthlyBudgetMicros: 1_000_000n,
      secretsMode: 'block',
    });
    await f.svc.ingest(host, batch());
    const types = (
      f.audit.recordSafely.mock.calls as unknown as Array<
        [unknown, string, { eventType: string; data: { limit?: string } }]
      >
    ).map((c) => `${c[2].eventType}:${c[2].data.limit}`);
    expect(types).toEqual([
      'ai_spend.limit_reached:budget',
      'ai_spend.limit_reached:cap',
    ]);
    await f.svc.ingest(host, batch({ batchId: 'b'.repeat(32) }));
    expect(f.audit.recordSafely).toHaveBeenCalledTimes(2); // already over: no repeat
    expect(await f.svc.doorConfig(host)).toEqual({
      secrets: 'block',
      paused: ['host.codex-cli'],
    });
  });

  it('keeps tenants apart: the config of another tenant sees nothing', async () => {
    const f = fake({ monthlyCapMicros: 1n, secretsMode: 'mask' });
    await f.svc.ingest(host, batch());
    expect(await f.svc.doorConfig({ tenantId: 't2' })).toEqual({
      secrets: 'mask',
      paused: [],
    });
  });
});
