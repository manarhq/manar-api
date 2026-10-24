import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import { RedisThrottlerStorageService } from '../rate-limit/redis-throttler-storage.service';
import { IdempotencyStoreService } from '../idempotency/idempotency-store.service';
import { LlmBudgetStore } from '../agent-runtime/llm-budget.store';
import { RedisPubSubService } from './live/redis-pubsub.service';
import { KafkaPublisherService } from './kafka-publisher.service';
import { AuditIndexerService } from './opensearch/audit-indexer.service';
import { WebhookDeliveryConsumerService } from '../webhooks/webhook-delivery-consumer.service';
import { OpenSearchIndexService } from './opensearch/opensearch-client.service';

/**
 * Every Redis, Kafka and OpenSearch client is built from the shared helpers, so a service that
 * goes back to `createClient({ url })` or `new Kafka({ kafkaJS: { brokers } })` drops TLS and
 * credentials and fails here.
 */
const calls = vi.hoisted(() => ({
  redis: [] as unknown[],
  kafka: [] as unknown[],
  opensearch: [] as unknown[],
}));

/** Any method resolves; `on`/`duplicate` chain; `get` returns null. */
function fake(): unknown {
  const target: Record<string, unknown> = {};
  const proxy: unknown = new Proxy(target, {
    get: (_t, prop) => {
      if (prop === 'then') return undefined;
      if (prop === 'isOpen' || prop === 'isReady') return true;
      if (prop === 'on' || prop === 'duplicate') return () => proxy;
      return () => Promise.resolve(prop === 'listTopics' ? [] : null);
    },
  });
  return proxy;
}

vi.mock('redis', () => ({
  createClient: (options: unknown) => {
    calls.redis.push(options);
    return fake();
  },
}));
vi.mock('@confluentinc/kafka-javascript', () => ({
  KafkaJS: {
    Kafka: class {
      constructor(config: unknown) {
        calls.kafka.push(config);
        return fake() as object;
      }
    },
  },
}));
vi.mock('@opensearch-project/opensearch', () => ({
  Client: class {
    constructor(options: unknown) {
      calls.opensearch.push(options);
      return fake() as object;
    }
  },
}));

const values: Partial<AppConfig> = {
  REDIS_URL: 'rediss://valkey-primary:6379',
  REDIS_USERNAME: 'manar-api',
  REDIS_PASSWORD: 'redis-pw',
  KAFKA_BROKERS: 'kafka:9093',
  KAFKA_CLIENT_ID: 'manar-api',
  KAFKA_AUDIT_TOPIC: 'manar.audit-events',
  KAFKA_SSL: 'true',
  KAFKA_SASL_MECHANISM: 'scram-sha-512',
  KAFKA_SASL_USERNAME: 'manar-api',
  KAFKA_SASL_PASSWORD: 'kafka-pw',
  OPENSEARCH_NODE: 'https://opensearch:9200',
  OPENSEARCH_AUDIT_INDEX: 'manar-audit-events',
  OPENSEARCH_USERNAME: 'manar-api',
  OPENSEARCH_PASSWORD: 'os-pw',
};
const config = {
  get: (key: keyof AppConfig) => values[key],
} as unknown as ConfigService<AppConfig, true>;
const any = {} as never;

const redisAuth = { username: 'manar-api', password: 'redis-pw' };
const kafkaAuth = {
  kafkaJS: expect.objectContaining({
    ssl: true,
    sasl: {
      mechanism: 'scram-sha-512',
      username: 'manar-api',
      password: 'kafka-pw',
    },
  }) as unknown,
};

beforeEach(() => {
  calls.redis.length = 0;
  calls.kafka.length = 0;
  calls.opensearch.length = 0;
});

describe('Redis clients use redisClientOptions', () => {
  it('rate-limit throttler storage', async () => {
    await new RedisThrottlerStorageService(config).onModuleInit();
    expect(calls.redis[0]).toMatchObject(redisAuth);
  });

  it('idempotency store', async () => {
    await new IdempotencyStoreService(config).onModuleInit();
    expect(calls.redis[0]).toMatchObject(redisAuth);
  });

  it('LLM budget store', async () => {
    await new LlmBudgetStore(config).used('t', 'task');
    expect(calls.redis[0]).toMatchObject(redisAuth);
  });

  it('live events pub/sub', async () => {
    await new RedisPubSubService(config).onModuleInit();
    expect(calls.redis[0]).toMatchObject(redisAuth);
  });
});

describe('Kafka clients use kafkaClientConfig', () => {
  it('audit publisher', async () => {
    await new KafkaPublisherService(config).onModuleInit();
    expect(calls.kafka[0]).toMatchObject(kafkaAuth);
  });

  it('audit indexer', async () => {
    await new AuditIndexerService(config, any, any).onModuleInit();
    expect(calls.kafka[0]).toMatchObject(kafkaAuth);
  });

  it('webhook delivery consumer', async () => {
    await new WebhookDeliveryConsumerService(config, any, any).onModuleInit();
    expect(calls.kafka[0]).toMatchObject(kafkaAuth);
  });
});

describe('OpenSearch client uses openSearchClientOptions', () => {
  it('index service', () => {
    new OpenSearchIndexService(config);
    expect(calls.opensearch[0]).toMatchObject({
      node: 'https://opensearch:9200',
      auth: { username: 'manar-api', password: 'os-pw' },
    });
  });
});
