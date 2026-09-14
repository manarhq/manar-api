import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { computeEventHash } from './audit-hash';
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

function fakeTenantClient(options: FakeClientOptions): {
  client: TenantPrismaClient;
  pageSizes: number[];
} {
  const pageSizes: number[] = [];
  const { events } = options;

  const client = {
    auditEvent: {
      findMany: (args: {
        where?: { sequence?: { gt?: number } };
        take?: number;
      }) => {
        const after = args.where?.sequence?.gt;
        const page = events
          .filter((event) => after === undefined || event.sequence > after)
          .slice(0, args.take);
        pageSizes.push(page.length);
        return Promise.resolve(page);
      },
    },
    auditChainAnchor: {
      findMany: () =>
        Promise.resolve(
          (options.anchorHashes ?? []).map((anchorHash) => ({ anchorHash })),
        ),
    },
    auditChainState: {
      findUnique: () =>
        Promise.resolve(
          options.hasChainState === false
            ? null
            : {
                id: AuditService.SINGLETON_ID,
                latestEventHash:
                  options.latestEventHash === undefined
                    ? (events[events.length - 1]?.eventHash ?? null)
                    : options.latestEventHash,
              },
        ),
    },
  } as unknown as TenantPrismaClient;

  return { client, pageSizes };
}

function makeService(): AuditService {
  const kafkaPublisher = {
    publish: () => Promise.resolve(),
  } as unknown as KafkaPublisherService;

  return new AuditService(kafkaPublisher);
}

describe('AuditService.verifyAuditChain', () => {
  it('validates a chain longer than one batch, paging through it rather than loading it whole', async () => {
    const events = buildChain(CHAIN_LENGTH);
    const { client, pageSizes } = fakeTenantClient({ events });

    await expect(makeService().verifyAuditChain(client)).resolves.toEqual({
      valid: true,
    });

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

    await expect(makeService().verifyAuditChain(client)).resolves.toEqual({
      valid: false,
      brokenAt: tampered.id,
    });

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
    await expect(makeService().verifyAuditChain(client)).resolves.toEqual({
      valid: false,
      brokenAt: orphaned.id,
    });
  });

  it('detects tampering in the FIRST batch too, at the right event', async () => {
    const events = buildChain(CHAIN_LENGTH);
    const tampered = events[3];
    if (tampered === undefined) throw new Error('fixture too short');
    tampered.eventType = 'authorization.denied';

    const { client } = fakeTenantClient({ events });

    await expect(makeService().verifyAuditChain(client)).resolves.toEqual({
      valid: false,
      brokenAt: tampered.id,
    });
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

    await expect(makeService().verifyAuditChain(client)).resolves.toEqual({
      valid: true,
    });
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

    await expect(makeService().verifyAuditChain(client)).resolves.toEqual({
      valid: false,
      brokenAt: orphanedHead.id,
    });
  });

  it('still checks the chain tail against AuditChainState after the last batch', async () => {
    const events = buildChain(CHAIN_LENGTH);
    const { client } = fakeTenantClient({
      events,
      latestEventHash: 'f'.repeat(64),
    });

    await expect(makeService().verifyAuditChain(client)).resolves.toEqual({
      valid: false,
      brokenAt: 'audit_chain_state',
    });
  });

  it('validates an empty chain without fetching a second page', async () => {
    const { client, pageSizes } = fakeTenantClient({
      events: [],
      hasChainState: false,
    });

    await expect(makeService().verifyAuditChain(client)).resolves.toEqual({
      valid: true,
    });
    expect(pageSizes).toEqual([0]);
  });
});
