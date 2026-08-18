import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { KafkaJS } from '@confluentinc/kafka-javascript';
import {
  AUDIT_EVENTS_TOPIC,
  CURRENT_EVENT_VERSION,
  DomainEventEnvelope,
} from '../src/audit/domain-event-envelope';

/**
 * Phase 9a (Section 29): "consumers must be idempotent — don't assume
 * exactly-once; a future indexer must upsert by `eventId`, not blindly
 * append." This is a small test consumer written just to prove that
 * envelope/idempotency contract against the real local Kafka broker
 * (`pnpm infra:up`'s `kafka` service) — Phase 9b's real indexer doesn't
 * exist yet, so there's no production consumer to test this against
 * instead. Publishes the same `eventId` twice (simulating an at-least-once
 * redelivery) and confirms a naive "upsert by `eventId`" consumer ends up
 * with exactly one record, not two.
 */
describe('Kafka consumer idempotency (e2e)', () => {
  const brokers = (process.env.KAFKA_BROKERS ?? 'localhost:29092')
    .split(',')
    .map((b) => b.trim());
  const kafka = new KafkaJS.Kafka({
    kafkaJS: { brokers, clientId: 'audit-kafka-idempotency-test' },
  });

  let producer: KafkaJS.Producer | undefined;
  let consumer: KafkaJS.Consumer | undefined;

  afterAll(async () => {
    await producer?.disconnect();
    await consumer?.disconnect();
  });

  it('redelivering the same eventId twice still upserts to exactly one record downstream', async () => {
    const admin = kafka.admin();
    await admin.connect();
    try {
      await admin.createTopics({
        topics: [
          { topic: AUDIT_EVENTS_TOPIC, numPartitions: 1, replicationFactor: 1 },
        ],
      });
    } finally {
      await admin.disconnect();
    }

    producer = kafka.producer();
    await producer.connect();

    const eventId = randomUUID();
    const tenantId = randomUUID();
    const envelope: DomainEventEnvelope = {
      eventId,
      eventType: 'task.created',
      eventVersion: CURRENT_EVENT_VERSION,
      tenantId,
      timestamp: new Date().toISOString(),
      correlationId: randomUUID(),
      actor: { type: 'system', id: 'idempotency-test' },
      data: { marker: 'first-delivery' },
    };
    const redelivered: DomainEventEnvelope = {
      ...envelope,
      // A redelivery of the SAME logical event carries a (possibly
      // slightly) different `data`/`timestamp` in a real at-least-once
      // system (e.g. a retried publish after a producer-side timeout whose
      // original send actually succeeded) -- what must stay constant, and
      // what the consumer's upsert keys on, is `eventId`.
      data: { marker: 'redelivered' },
    };

    // Publish the same eventId twice, deliberately.
    await producer.send({
      topic: AUDIT_EVENTS_TOPIC,
      messages: [{ key: tenantId, value: JSON.stringify(envelope) }],
    });
    await producer.send({
      topic: AUDIT_EVENTS_TOPIC,
      messages: [{ key: tenantId, value: JSON.stringify(redelivered) }],
    });

    // A naive consumer that upserts a Map keyed by eventId -- standing in
    // for "Phase 9b's real indexer does `INSERT ... ON CONFLICT (eventId)
    // DO UPDATE`", the exact contract Section 29 requires.
    const upserted = new Map<string, DomainEventEnvelope>();
    let messagesSeen = 0;

    consumer = kafka.consumer({
      kafkaJS: {
        groupId: `audit-kafka-idempotency-test-${randomUUID()}`,
        fromBeginning: true,
      },
    });
    await consumer.connect();
    await consumer.subscribe({ topic: AUDIT_EVENTS_TOPIC });

    const consumedBothOwnMessages = new Promise<void>((resolve) => {
      void consumer!.run({
        eachMessage: ({ message }) => {
          const value = message.value?.toString('utf8');
          if (!value) return Promise.resolve();
          const parsed = JSON.parse(value) as DomainEventEnvelope;
          if (parsed.eventId !== eventId) return Promise.resolve(); // another test/run's message on the shared topic
          upserted.set(parsed.eventId, parsed); // upsert by eventId, never append
          messagesSeen += 1;
          if (messagesSeen >= 2) resolve();
          return Promise.resolve();
        },
      });
    });

    // Bounded wait -- if only one of the two redeliveries ever arrives
    // (e.g. a slow broker), fail loudly rather than hang forever.
    await Promise.race([
      consumedBothOwnMessages,
      new Promise((_, reject) =>
        setTimeout(
          () => reject(new Error('Timed out waiting for both redeliveries')),
          20_000,
        ),
      ),
    ]);

    // Both raw Kafka messages arrived (the topic really did carry the
    // event twice)...
    expect(messagesSeen).toBe(2);
    // ...but the upsert-by-eventId consumer ends up with exactly one
    // record for it, not two -- Section 29's idempotency contract, proven
    // against the real broker.
    expect(upserted.size).toBe(1);
    expect(upserted.get(eventId)?.data).toEqual({ marker: 'redelivered' });
  }, 30_000);
});
