import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { kafkaClientConfig, type KafkaConfig } from './kafka.config';
import { redisClientOptions, type RedisConfig } from './live/redis.config';
import {
  openSearchClientOptions,
  type OpenSearchConfig,
} from './opensearch/opensearch.config';

const ca = join(mkdtempSync(join(tmpdir(), 'manar-tls-')), 'ca.pem');
writeFileSync(ca, 'PEM');

const getter =
  <C>(values: Partial<C>) =>
  <K extends keyof C>(key: K) =>
    values[key] as C[K];

describe('Redis client options', () => {
  const opts = (v: Partial<RedisConfig>) =>
    redisClientOptions(getter<RedisConfig>(v), { connectTimeout: 1 });

  it('plain URL and no credentials stays as before', () => {
    expect(opts({ REDIS_URL: 'redis://r:6379' })).toEqual({
      url: 'redis://r:6379',
      socket: { connectTimeout: 1 },
    });
  });

  it('passes ACL credentials and the CA for rediss://', () => {
    const o = opts({
      REDIS_URL: 'rediss://r:6379',
      REDIS_USERNAME: 'manar-api',
      REDIS_PASSWORD: 'pw',
      REDIS_TLS_CA_FILE: ca,
    });
    expect(o).toMatchObject({
      username: 'manar-api',
      password: 'pw',
      socket: { connectTimeout: 1, tls: true },
    });
    expect(String(o.socket.ca)).toBe('PEM');
  });

  it('refuses a CA file with a plaintext URL', () => {
    expect(() =>
      opts({ REDIS_URL: 'redis://r:6379', REDIS_TLS_CA_FILE: ca }),
    ).toThrow(/rediss/);
  });
});

describe('OpenSearch client options', () => {
  const opts = (v: Partial<OpenSearchConfig>) =>
    openSearchClientOptions(getter<OpenSearchConfig>(v));

  it('basic auth and CA for an https node', () => {
    const o = opts({
      OPENSEARCH_NODE: 'https://os:9200',
      OPENSEARCH_USERNAME: 'manar-api',
      OPENSEARCH_PASSWORD: 'pw',
      OPENSEARCH_TLS_CA_FILE: ca,
    });
    expect(o.auth).toEqual({ username: 'manar-api', password: 'pw' });
    expect(String(o.ssl?.ca)).toBe('PEM');
  });

  it('refuses half a credential pair and a CA for http', () => {
    expect(() =>
      opts({ OPENSEARCH_NODE: 'https://os', OPENSEARCH_USERNAME: 'u' }),
    ).toThrow(/both/);
    expect(() =>
      opts({ OPENSEARCH_NODE: 'http://os', OPENSEARCH_TLS_CA_FILE: ca }),
    ).toThrow(/https/);
  });
});

describe('Kafka client config', () => {
  const cfg = (v: Partial<KafkaConfig>) =>
    kafkaClientConfig(
      getter<KafkaConfig>({ KAFKA_BROKERS: 'a:9092, b:9092', ...v }),
      'id',
    );

  it('plaintext by default', () => {
    expect(cfg({})).toEqual({
      kafkaJS: { brokers: ['a:9092', 'b:9092'], clientId: 'id' },
    });
  });

  it('TLS with SCRAM and a CA', () => {
    expect(
      cfg({
        KAFKA_SSL: 'true',
        KAFKA_SSL_CA_FILE: ca,
        KAFKA_SASL_MECHANISM: 'scram-sha-512',
        KAFKA_SASL_USERNAME: 'manar-api',
        KAFKA_SASL_PASSWORD: 'pw',
      }),
    ).toEqual({
      kafkaJS: {
        brokers: ['a:9092', 'b:9092'],
        clientId: 'id',
        ssl: true,
        sasl: {
          mechanism: 'scram-sha-512',
          username: 'manar-api',
          password: 'pw',
        },
      },
      'ssl.ca.location': ca,
    });
  });

  it('refuses half-configured connections', () => {
    expect(() => cfg({ KAFKA_SSL_CA_FILE: ca })).toThrow(/KAFKA_SSL/);
    expect(() => cfg({ KAFKA_SASL_MECHANISM: 'scram-sha-512' })).toThrow(
      /USERNAME/,
    );
    expect(() =>
      cfg({
        KAFKA_SASL_MECHANISM: 'plain',
        KAFKA_SASL_USERNAME: 'u',
        KAFKA_SASL_PASSWORD: 'p',
      }),
    ).toThrow(/KAFKA_SSL=true/);
  });
});
