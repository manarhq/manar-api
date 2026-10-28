import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { computeEventHash } from './audit-hash';
import { partitionFor } from './audit-partition';
import type { CheckpointKeyLookup } from './checkpoint/checkpoint-format';
import { AuditService } from './audit.service';
import type { KafkaPublisherService } from './kafka-publisher.service';

/**
 * `verifyAuditChain`'s batching tests.
 *
 * Release 2026-11-11 replaced a single whole-table `findMany` with a
 * keyset-paginated walk, because `GET /audit/verify` is reachable over HTTP
 * and a large tenant's chain was enough to OOM-kill a 768Mi pod. Batching a
 * hash-chain check is exactly the kind of change that can silently weaken
 * it — a linkage checked *within* a batch but not *across* one would still
 * pass every single-batch test, while quietly failing to detect tampering
 * anywhere past the first page.
 *
 * So every scenario below is built with a batch size deliberately smaller
 * than the chain, and the load-bearing test puts the tampered event in the
 * *second* batch. The fake tenant client implements the same
 * `where: { sequence: { gt } } / orderBy / take` contract Prisma does, and
 * records how many pages were requested, so "it batched" and "it still
 * detects tampering" are asserted by the same test.
 */

/** Must stay ABOVE `AuditService.VERIFY_CHAIN_BATCH_SIZE` (1000) — a single-page chain would prove nothing here. */
const CHAIN_LENGTH = 2500;

interface StoredEvent {
  id: string;
  sequence: number;
  eventType: string;
  correlationId: string;
  actor: unknown;
  timestamp: Date;
  data: unknown;
  previousHash: string | null;
  eventHash: string;
  partition: number;
  partitionSeq: bigint;
  createdAt: Date;
}

/**
 * Builds a genuinely valid chain: each event's `previousHash` is the
 * previous event's `eventHash`, and each `eventHash` is the real
 * `computeEventHash` of its own content — the same function the production
 * write path uses, so nothing here can pass by agreeing with a
 * reimplementation of the hash.
 */
function buildChain(length: number): StoredEvent[] {
  const events: StoredEvent[] = [];
  let previousHash: string | null = null;

  for (let index = 0; index < length; index += 1) {
    const id = randomUUID();
    const content = {
      id,
      eventType: 'authorization.allowed',
      correlationId: `correlation-${index}`,
      actor: { type: 'system', id: 'system:test' },
      timestamp: new Date(Date.UTC(2026, 10, 11, 0, 0, index)).toISOString(),
      data: { index },
      previousHash,
    };
    const eventHash = computeEventHash(content);

    events.push({
      id,
      sequence: index + 1,
      eventType: content.eventType,
      correlationId: content.correlationId,
      actor: content.actor,
      timestamp: new Date(content.timestamp),
      data: content.data,
      previousHash,
      eventHash,
      partition: 0,
      partitionSeq: BigInt(index + 1),
      createdAt: new Date(content.timestamp),
    });
    previousHash = eventHash;
  }

  return events;
}

interface FakeClientOptions {
  events: StoredEvent[];
  anchorHashes?: string[];
  /** Omit for "the bookkeeping row agrees with the chain's tail". */
  latestEventHash?: string | null;
  hasChainState?: boolean;
}

/**
 * Implements the same per-partition keyset contract Prisma does
 * (`where: { partition, partitionSeq: { gt } }`, ordered by `partitionSeq`,
 * `take`), and records each page's size.
 */
function fakeTenantClient(options: FakeClientOptions): {
  client: TenantPrismaClient;
  pageSizes: number[];
} {
  const pageSizes: number[] = [];
  const { events } = options;

  const client = {
    auditEvent: {
      findMany: (args: {
        where: { partition: number; partitionSeq?: { gt?: bigint } };
        take?: number;
      }) => {
        const after = args.where.partitionSeq?.gt;
        const page = events
          .filter(
            (event) =>
              event.partition === args.where.partition &&
              (after === undefined || event.partitionSeq > after),
          )
          .sort((a, b) => (a.partitionSeq < b.partitionSeq ? -1 : 1))
          .slice(0, args.take);
        pageSizes.push(page.length);
        return Promise.resolve(page);
      },
    },
    auditChainAnchor: {
      findMany: () =>
        Promise.resolve(
          (options.anchorHashes ?? []).map((anchorHash) => ({
            anchorHash,
            partition: 0,
          })),
        ),
    },
    // No SEALs in these fixtures: the checkpoint walk finds nothing to check.
    $queryRaw: () => Promise.resolve([]),
    auditCheckpoint: { findMany: () => Promise.resolve([]) },
    auditPartitionState: {
      findMany: () =>
        Promise.resolve(
          options.hasChainState === false
            ? []
            : [
                {
                  partition: 0,
                  latestEventHash:
                    options.latestEventHash === undefined
                      ? (events[events.length - 1]?.eventHash ?? null)
                      : options.latestEventHash,
                },
              ],
        ),
    },
  } as unknown as TenantPrismaClient;

  return { client, pageSizes };
}

function makeService(): AuditService {
  const kafkaPublisher = {
    publish: () => Promise.resolve(),
  } as unknown as KafkaPublisherService;

  return new AuditService(kafkaPublisher, {} as CheckpointKeyLookup);
}

describe('AuditService.verifyAuditChain', () => {
  it('validates a chain longer than one batch, paging through it rather than loading it whole', async () => {
    const events = buildChain(CHAIN_LENGTH);
    const { client, pageSizes } = fakeTenantClient({ events });

    await expect(makeService().verifyAuditChain(client, 't1')).resolves.toEqual(
      {
        valid: true,
      },
    );

    // The memory fix itself: more than one page was fetched, and no single
    // page held the whole table.
    expect(pageSizes.length).toBeGreaterThan(1);
    expect(Math.max(...pageSizes)).toBeLessThan(CHAIN_LENGTH);
  });

  it('detects a tampered event in the SECOND batch, not just the first', async () => {
    const events = buildChain(CHAIN_LENGTH);

    // Index 1500 is past the 1000-row batch boundary, so catching it
    // requires the running hash to have survived the page break. Mutating
    // `data` without recomputing `eventHash` is exactly what an attacker
    // editing the table directly would leave behind.
    const tampered = events[1500];
    if (tampered === undefined) throw new Error('fixture too short');
    tampered.data = { index: 1500, injected: 'tampered' };

    const { client, pageSizes } = fakeTenantClient({ events });

    await expect(makeService().verifyAuditChain(client, 't1')).resolves.toEqual(
      {
        valid: false,
        brokenAt: tampered.id,
      },
    );

    // Proves the detection happened after a page boundary rather than
    // inside the first page.
    expect(pageSizes.length).toBeGreaterThan(1);
  });

  it('detects a removed event across a batch boundary, reporting the row whose linkage broke', async () => {
    const events = buildChain(CHAIN_LENGTH);
    const orphaned = events[1201];
    if (orphaned === undefined) throw new Error('fixture too short');
    events.splice(1200, 1);

    const { client } = fakeTenantClient({ events });

    // The next event's `previousHash` now points at a hash no remaining
    // event has — the deletion is caught at the row that lost its parent.
    await expect(makeService().verifyAuditChain(client, 't1')).resolves.toEqual(
      {
        valid: false,
        brokenAt: orphaned.id,
      },
    );
  });

  it('detects tampering in the FIRST batch too, at the right event', async () => {
    const events = buildChain(CHAIN_LENGTH);
    const tampered = events[3];
    if (tampered === undefined) throw new Error('fixture too short');
    tampered.eventType = 'authorization.denied';

    const { client } = fakeTenantClient({ events });

    await expect(makeService().verifyAuditChain(client, 't1')).resolves.toEqual(
      {
        valid: false,
        brokenAt: tampered.id,
      },
    );
  });

  it('stays anchor-aware across batching: a retention-pruned head validates against a known anchor', async () => {
    const full = buildChain(CHAIN_LENGTH);
    // Simulate `AuditRetentionWorkflow` having pruned the first 900 events
    // and recorded the last pruned event's hash as an anchor.
    const anchorHash = full[899]?.eventHash;
    if (anchorHash === undefined) throw new Error('fixture too short');
    const remaining = full.slice(900);

    const { client } = fakeTenantClient({
      events: remaining,
      anchorHashes: [anchorHash],
    });

    await expect(makeService().verifyAuditChain(client, 't1')).resolves.toEqual(
      {
        valid: true,
      },
    );
  });

  it('rejects a pruned head whose previousHash matches no known anchor', async () => {
    const full = buildChain(CHAIN_LENGTH);
    const remaining = full.slice(900);
    const orphanedHead = remaining[0];
    if (orphanedHead === undefined) throw new Error('fixture too short');

    const { client } = fakeTenantClient({
      events: remaining,
      anchorHashes: ['0'.repeat(64)],
    });

    await expect(makeService().verifyAuditChain(client, 't1')).resolves.toEqual(
      {
        valid: false,
        brokenAt: orphanedHead.id,
      },
    );
  });

  it("still checks the chain tail against its partition's AuditPartitionState after the last batch", async () => {
    const events = buildChain(CHAIN_LENGTH);
    const { client } = fakeTenantClient({
      events,
      latestEventHash: 'f'.repeat(64),
    });

    await expect(makeService().verifyAuditChain(client, 't1')).resolves.toEqual(
      {
        valid: false,
        brokenAt: 'audit_partition_state:0',
      },
    );
  });

  it('validates an empty chain without fetching a second page', async () => {
    const { client, pageSizes } = fakeTenantClient({
      events: [],
      hasChainState: false,
    });

    await expect(makeService().verifyAuditChain(client, 't1')).resolves.toEqual(
      {
        valid: true,
      },
    );
    // One empty page per partition, never a second page for any of them.
    expect(pageSizes).toEqual(new Array(64).fill(0));
  });
});

/** An agent id that `partitionFor` puts in partition `target`. */
function agentInPartition(target: number): string {
  for (let i = 0; ; i += 1) {
    const id = `agent-${i}`;
    if (partitionFor({ type: 'agent', id }, null) === target) return id;
  }
}

interface FakeTx {
  tx: unknown;
  lockedPartitions: number[][];
  inserted: Record<string, unknown>[];
}

/** A transaction client that keeps partition state in memory, like the real tables would. */
function fakeWriteTx(): FakeTx {
  const state = new Map<number, { hash: string | null; seq: bigint }>();
  const lockedPartitions: number[][] = [];
  const inserted: Record<string, unknown>[] = [];
  let sequence = 0;
  const tx = {
    auditPartitionState: {
      createMany: ({ data }: { data: { partition: number }[] }) => {
        for (const { partition } of data) {
          if (!state.has(partition))
            state.set(partition, { hash: null, seq: 0n });
        }
        return Promise.resolve({ count: data.length });
      },
    },
    $queryRaw: (_strings: TemplateStringsArray, ...values: unknown[]) => {
      const partitions = values[0] as number[];
      lockedPartitions.push([...partitions]);
      return Promise.resolve(
        partitions.map((partition) => ({
          partition,
          latestEventHash: state.get(partition)!.hash,
          latestSeq: state.get(partition)!.seq,
        })),
      );
    },
    auditEvent: {
      createManyAndReturn: ({ data }: { data: Record<string, unknown>[] }) => {
        const rows: Record<string, unknown>[] = data.map((row) => ({
          ...row,
          sequence: (sequence += 1),
          createdAt: new Date(),
        }));
        inserted.push(...rows);
        for (const row of rows) {
          state.set(row.partition as number, {
            hash: row.eventHash as string,
            seq: row.partitionSeq as bigint,
          });
        }
        return Promise.resolve(rows);
      },
    },
    $executeRaw: () => Promise.resolve(1),
  };
  return { tx, lockedPartitions, inserted };
}

function writeClient(fake: FakeTx, fail?: Error): TenantPrismaClient {
  return {
    $transaction: (fn: (tx: unknown) => Promise<unknown>) =>
      fail ? Promise.reject(fail) : fn(fake.tx),
  } as unknown as TenantPrismaClient;
}

describe('AuditService.record (partitioned, group commit)', () => {
  it("chains each agent's events within its own partition, in order", async () => {
    const fake = fakeWriteTx();
    const service = makeService();
    const client = writeClient(fake);
    const agent = agentInPartition(5);

    const events = await Promise.all(
      [1, 2, 3].map((n) =>
        service.record(client, 'tenant-1', {
          eventType: 'authorization.allowed',
          actor: { type: 'agent', id: agent },
          data: { n },
        }),
      ),
    );

    expect(events.map((e) => e.partition)).toEqual([5, 5, 5]);
    expect(events.map((e) => e.partitionSeq)).toEqual([1n, 2n, 3n]);
    expect(events[0]!.previousHash).toBeNull();
    expect(events[1]!.previousHash).toBe(events[0]!.eventHash);
    expect(events[2]!.previousHash).toBe(events[1]!.eventHash);
    expect(events[2]!.eventHash).toBe(
      computeEventHash({
        id: events[2]!.id,
        eventType: 'authorization.allowed',
        correlationId: events[2]!.correlationId,
        actor: { type: 'agent', id: agent },
        timestamp: events[2]!.timestamp.toISOString(),
        data: { n: 3 },
        previousHash: events[1]!.eventHash,
      }),
    );
    await service.onModuleDestroy();
  });

  it('locks the partitions a batch touches in ascending order', async () => {
    const fake = fakeWriteTx();
    const service = makeService();
    const client = writeClient(fake);

    await Promise.all(
      [9, 3, 9].map((p) =>
        service.record(client, 'tenant-1', {
          eventType: 'authorization.allowed',
          actor: { type: 'agent', id: agentInPartition(p) },
          data: {},
        }),
      ),
    );

    expect(fake.lockedPartitions).toEqual([[3, 9]]);
    await service.onModuleDestroy();
  });

  it('rejects every caller of a failed batch, and recordSafely returns undefined', async () => {
    const fake = fakeWriteTx();
    const service = makeService();
    const client = writeClient(fake, new Error('disk full'));
    const input = {
      eventType: 'authorization.allowed' as const,
      actor: { type: 'agent' as const, id: 'a1' },
      data: {},
    };

    const strict = service.record(client, 'tenant-1', input);
    const safe = service.recordSafely(client, 'tenant-1', input);

    await expect(strict).rejects.toThrow('disk full');
    await expect(safe).resolves.toBeUndefined();
    expect(fake.inserted).toHaveLength(0);
    await service.onModuleDestroy();
  });

  it('a poison event fails alone: its batch-mates still commit', async () => {
    const fake = fakeWriteTx();
    const service = makeService();
    // Postgres refuses the whole insert when any row is bad (here: data with
    // U+0000, which jsonb rejects); a lone retry of each row isolates it.
    const client = {
      $transaction: (fn: (tx: unknown) => Promise<unknown>) => {
        const tx = fake.tx as {
          auditEvent: {
            createManyAndReturn: (a: { data: { data: unknown }[] }) => unknown;
          };
        };
        const real = tx.auditEvent.createManyAndReturn;
        return fn({
          ...tx,
          auditEvent: {
            createManyAndReturn: (args: { data: { data: unknown }[] }) =>
              args.data.some((r) => JSON.stringify(r.data).includes('\\u0000'))
                ? Promise.reject(
                    new Error('unsupported Unicode escape sequence'),
                  )
                : real(args),
          },
        });
      },
    } as unknown as TenantPrismaClient;
    const record = (data: unknown) =>
      service.record(client, 'tenant-1', {
        eventType: 'authorization.allowed',
        actor: { type: 'agent', id: 'a1' },
        data,
      });

    const results = await Promise.allSettled([
      record({ n: 1 }),
      record({ text: 'bad\u0000' }),
      record({ n: 3 }),
    ]);

    expect(results.map((r) => r.status)).toEqual([
      'fulfilled',
      'rejected',
      'fulfilled',
    ]);
    expect(fake.inserted).toHaveLength(2);
    const [first, , third] = results as PromiseFulfilledResult<{
      eventHash: string;
      previousHash: string | null;
    }>[];
    expect(third!.value.previousHash).toBe(first!.value.eventHash);
    await service.onModuleDestroy();
  });

  it('publishes each committed event to Kafka with its partition position', async () => {
    const publish = vi.fn(() => Promise.resolve());
    const service = new AuditService(
      { publish } as unknown as KafkaPublisherService,
      {} as CheckpointKeyLookup,
    );
    const fake = fakeWriteTx();

    const event = await service.record(writeClient(fake), 'tenant-1', {
      eventType: 'authorization.allowed',
      actor: { type: 'agent', id: agentInPartition(2) },
      data: {},
    });

    expect(publish).toHaveBeenCalledWith(
      expect.objectContaining({
        eventId: event.id,
        tenantId: 'tenant-1',
        partition: 2,
        partitionSeq: '1',
      }),
    );
    await service.onModuleDestroy();
  });
});
