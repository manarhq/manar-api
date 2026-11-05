import { describe, expect, it, vi } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { OpenSearchIndexService } from './opensearch-client.service';
import type { RedisPubSubService } from '../live/redis-pubsub.service';
import { AuditIndexerService } from './audit-indexer.service';

const msg = (n: number, tenantId = 't1') =>
  JSON.stringify({
    eventId: `e${n}`,
    tenantId,
    sequence: n,
    eventType: 'x.y',
    correlationId: 'c',
    actor: {},
    timestamp: '2026-11-05T00:00:00.000Z',
    data: {},
  });

function setup(
  bulk: (docs: { eventId: string }[]) => Promise<{
    rejected: { eventId: string; reason: string }[];
  }> = () => Promise.resolve({ rejected: [] }),
) {
  const os = { bulkUpsertAuditEvents: vi.fn(bulk) };
  const redis = { publish: vi.fn(() => Promise.resolve()) };
  const indexer = new AuditIndexerService(
    {} as ConfigService<never, true>,
    os as unknown as OpenSearchIndexService,
    redis as unknown as RedisPubSubService,
  );
  return { indexer, os, redis };
}

describe('AuditIndexerService.handleBatch', () => {
  it('indexes a batch with ONE bulk call and no per-event refresh, keeping each tenant on its own document', async () => {
    const { indexer, os, redis } = setup();
    await indexer.handleBatch([
      msg(1),
      msg(2, 't2'),
      undefined,
      'not json',
      msg(3),
    ]);
    expect(os.bulkUpsertAuditEvents).toHaveBeenCalledTimes(1);
    const [docs, opts] = os.bulkUpsertAuditEvents.mock.calls[0] as unknown as [
      { eventId: string; tenantId: string }[],
      { refresh: boolean },
    ];
    expect(docs.map((d) => [d.eventId, d.tenantId])).toEqual([
      ['e1', 't1'],
      ['e2', 't2'],
      ['e3', 't1'],
    ]);
    expect(opts).toEqual({ refresh: false });
    expect(redis.publish).toHaveBeenCalledTimes(3);
  });

  it('throws when OpenSearch cannot take the batch, so the consumer redelivers it', async () => {
    const { indexer, redis } = setup(() =>
      Promise.reject(new Error('ECONNREFUSED')),
    );
    await expect(indexer.handleBatch([msg(1), msg(2)])).rejects.toThrow(
      'ECONNREFUSED',
    );
    expect(redis.publish).toHaveBeenCalledTimes(2); // the live feed does not wait for indexing
  });

  it('logs and skips items the index refuses for good; the batch still completes', async () => {
    const { indexer } = setup(() =>
      Promise.resolve({
        rejected: [{ eventId: 'e2', reason: 'mapper_parsing_exception' }],
      }),
    );
    await expect(
      indexer.handleBatch([msg(1), msg(2), msg(3)]),
    ).resolves.toBeUndefined();
  });

  it('bounds batches', () => {
    expect(AuditIndexerService.BATCH_MAX).toBeLessThanOrEqual(500);
    expect(AuditIndexerService.FLUSH_MS).toBeLessThanOrEqual(1000);
  });
});
