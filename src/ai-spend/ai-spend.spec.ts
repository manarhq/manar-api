import { describe, expect, it, vi } from 'vitest';
import {
  AiSpendService,
  AiUsageBatchSchema,
  BOUNDS,
  boundsProblem,
  type AiUsageBatch,
} from './ai-spend.service';
import { costMicros, isPriced } from './pricing';

type Usage = { hostId: string; toolId: string; costMicros: bigint };
type Host = { id: string; ownerSubject: string | null };

function fake(
  settings: Record<string, unknown> | null = null,
  hosts: Host[] = [],
) {
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
        deleteMany: () => Promise.resolve({}),
      },
      aiUsageDaily: {
        upsert: ({ create }: { create: Usage }) => {
          rows.push(create);
          return Promise.resolve({});
        },
        groupBy: ({ where }: { where: { hostId?: { in: string[] } } }) => {
          const by = new Map<string, bigint>();
          for (const r of rows) {
            if (where.hostId && !where.hostId.in.includes(r.hostId)) continue;
            const k = `${r.toolId}|${r.hostId}`;
            by.set(k, (by.get(k) ?? 0n) + r.costMicros);
          }
          return Promise.resolve(
            [...by].map(([k, v]) => {
              const [toolId, hostId] = k.split('|');
              return { toolId, hostId, _sum: { costMicros: v } };
            }),
          );
        },
      },
      host: {
        findMany: ({ where }: { where: { ownerSubject?: string } }) =>
          Promise.resolve(
            hosts.filter((h) => h.ownerSubject === where.ownerSubject),
          ),
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
    svc: new AiSpendService(tenants as never, audit as never),
  };
}

let n = 0;
const batch = (over: Partial<AiUsageBatch> = {}): AiUsageBatch => ({
  batchId: (++n).toString(16).padStart(32, '0'),
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
const host = (hostId = 'h1', ownerSubject: string | null = 'alice') => ({
  hostId,
  tenantId: 't1',
  ownerSubject,
});
type Call = [
  unknown,
  string,
  { eventType: string; data: Record<string, unknown> },
];
const events = (f: ReturnType<typeof fake>) =>
  (f.audit.recordSafely.mock.calls as unknown as Call[]).map((c) => c[2]);

describe('pricing', () => {
  it('prices by longest prefix and leaves unknown models at zero', () => {
    expect(costMicros('gpt-5', 1_000_000, 100_000)).toBe(2_250_000);
    expect(costMicros('gpt-5-mini-2026', 1_000_000, 0)).toBe(250_000);
    expect(isPriced('mystery-model')).toBe(false);
    expect(costMicros('mystery-model', 5, 5)).toBe(0);
  });
});

describe('batch schema and bounds', () => {
  it('refuses unknown tools, odd model names and unmasked samples', () => {
    const bad = (o: Partial<AiUsageBatch>) =>
      AiUsageBatchSchema.safeParse(batch(o)).success;
    expect(bad({})).toBe(true);
    expect(
      bad({ usage: [{ ...batch().usage[0]!, toolId: 'host.evil' }] }),
    ).toBe(false);
    expect(
      bad({ usage: [{ ...batch().usage[0]!, toolId: 'other:unknown' }] }),
    ).toBe(true);
    expect(
      bad({ usage: [{ ...batch().usage[0]!, model: 'gpt 5; drop' }] }),
    ).toBe(false);
    const g = {
      toolId: 'host.codex-cli',
      kind: 'aws_access_key',
      action: 'masked' as const,
      count: 1,
    };
    expect(bad({ guard: [{ ...g, sample: 'AKIAIOSFODNN7EXAMPLE' }] })).toBe(
      false,
    );
    expect(bad({ guard: [{ ...g, sample: 'AKIA****' }] })).toBe(true);
  });

  it('flags counts no real device reaches', () => {
    const u = batch().usage[0]!;
    expect(boundsProblem(batch())).toBeNull();
    expect(
      boundsProblem(
        batch({ usage: [{ ...u, inputTokens: BOUNDS.inputPerRecord + 1 }] }),
      ),
    ).toMatch(/input/);
    expect(
      boundsProblem(batch({ usage: Array.from({ length: 101 }, () => u) })),
    ).toMatch(/records/);
    const heavy = { ...u, inputTokens: 400_000_000, outputTokens: 90_000_000 };
    expect(boundsProblem(batch({ usage: [heavy, heavy, heavy] }))).toMatch(
      /batch/,
    );
  });
});

describe('submit', () => {
  it('rejects an out-of-bound report with 400 and an audit event, and stores nothing', async () => {
    const f = fake();
    const u = batch().usage[0]!;
    await expect(
      f.svc.submit(
        host(),
        batch({ usage: [{ ...u, inputTokens: 9_000_000_000 }] }),
      ),
    ).rejects.toMatchObject({ status: 400 });
    expect(f.rows).toHaveLength(0);
    expect(events(f)[0]).toMatchObject({
      eventType: 'door.usage.rejected',
      data: { hostId: 'h1' },
    });
    await expect(f.svc.submit(host(), { nope: 1 })).rejects.toMatchObject({
      status: 400,
    });
  });

  it('limits reports per device', async () => {
    const f = fake();
    for (let i = 0; i < BOUNDS.reportsPerWindow; i++)
      await f.svc.submit(host(), batch());
    await expect(f.svc.submit(host(), batch())).rejects.toMatchObject({
      status: 429,
    });
    await expect(f.svc.submit(host('h2'), batch())).resolves.toBeTruthy(); // another device is not limited
  });
});

describe('ingest', () => {
  it('counts a batch id once and audits masked samples only', async () => {
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
    expect((await f.svc.ingest(host(), b)).accepted).toBe(true);
    expect((await f.svc.ingest(host(), b)).accepted).toBe(false); // replay
    expect(f.rows).toHaveLength(1);
    expect(f.rows[0]!.costMicros).toBe(2_250_000n);
    expect(events(f)).toHaveLength(1);
    expect(events(f)[0]).toMatchObject({
      eventType: 'door.secret.blocked',
      data: { sample: 'AKIA****', count: 3 },
    });
  });

  it('pauses a tool only for the owner whose devices reached the cap', async () => {
    const hosts = [
      { id: 'h1', ownerSubject: 'alice' },
      { id: 'h2', ownerSubject: 'alice' },
      { id: 'h3', ownerSubject: 'bob' },
    ];
    const f = fake(
      { monthlyCapMicros: 3_000_000n, secretsMode: 'block' },
      hosts,
    );
    await f.svc.ingest(host('h1'), batch()); // alice: 2.25
    await f.svc.ingest(host('h2'), batch()); // alice: 4.5 -> over the 3.0 cap
    const limit = events(f).filter(
      (e) => e.eventType === 'ai_spend.limit_reached',
    );
    expect(limit).toHaveLength(1);
    expect(limit[0]!.data).toMatchObject({
      limit: 'cap',
      scope: 'owner',
      toolId: 'host.codex-cli',
    });
    expect(limit[0]!.data.contributors).toHaveLength(2); // which devices added up to it
    expect(await f.svc.doorConfig(host('h1'))).toEqual({
      secrets: 'block',
      paused: ['host.codex-cli'],
    });
    expect(await f.svc.doorConfig(host('h2'))).toEqual({
      secrets: 'block',
      paused: ['host.codex-cli'],
    });
    expect(await f.svc.doorConfig(host('h3', 'bob'))).toEqual({
      secrets: 'block',
      paused: [],
    });
  });

  it('a workspace-scope cap counts every device together', async () => {
    const hosts = [
      { id: 'h1', ownerSubject: 'alice' },
      { id: 'h3', ownerSubject: 'bob' },
    ];
    const f = fake(
      { monthlyCapMicros: 3_000_000n, capScope: 'workspace' },
      hosts,
    );
    await f.svc.ingest(host('h1'), batch());
    await f.svc.ingest(host('h3', 'bob'), batch());
    expect((await f.svc.doorConfig(host('h3', 'bob'))).paused).toEqual([
      'host.codex-cli',
    ]);
    expect(
      events(f).find((e) => e.eventType === 'ai_spend.limit_reached')!.data,
    ).toMatchObject({ scope: 'workspace' });
  });

  it('alerts once when the workspace passes its budget', async () => {
    const f = fake({ monthlyBudgetMicros: 2_000_000n }, [
      { id: 'h1', ownerSubject: 'alice' },
    ]);
    await f.svc.ingest(host(), batch());
    await f.svc.ingest(host(), batch());
    expect(events(f).filter((e) => e.data.limit === 'budget')).toHaveLength(1);
  });

  it('keeps tenants apart', async () => {
    const f = fake({ monthlyCapMicros: 1n });
    await f.svc.ingest(host(), batch());
    expect(
      await f.svc.doorConfig({
        hostId: 'x',
        tenantId: 't2',
        ownerSubject: null,
      }),
    ).toEqual({ secrets: 'mask', paused: [] });
  });
});
