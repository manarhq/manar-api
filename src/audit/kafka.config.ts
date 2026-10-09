import { z } from 'zod';

/**
 * Phase 9a (Audit Chain & Kafka Event Backbone) — connection settings for
 * `KafkaPublisherService`. Read by every process that records audit events:
 * both Fastify HTTP apps (`AppModule`/`AgentMtlsAppModule`) and the separate
 * Temporal worker process (`src/worker.main.ts`) — see docs/audit-chain.md.
 */
export const KafkaConfigSchema = z.object({
  /**
   * Comma-separated `host:port` list. Defaults to the `PLAINTEXT_HOST`
   * listener `deploy/docker-compose.yml`'s `kafka` service publishes on
   * `localhost:29092` — every process that reads this config (the HTTP
   * apps, the worker process, and every test suite) runs on the host, never
   * inside the compose network itself, so the host-mapped listener (not the
   * internal `kafka:9092` one other *containers* would use) is the correct
   * default here.
   */
  KAFKA_BROKERS: z.string().min(1).default('localhost:29092'),
  /** Identifies this process to the broker (shows up in broker-side connection logs/metrics) — distinct per logical process is nice-to-have, not required, so one fixed default is fine. */
  KAFKA_CLIENT_ID: z.string().min(1).default('manar-api'),
  /** Matches `AUDIT_EVENTS_TOPIC` (`domain-event-envelope.ts`) — kept as a real config field (not a hardcoded import of that constant) so a deployment can rename the topic without a code change, same "typed-config, optional override" posture `OPENFGA_STORE_NAME`/`OPENFGA_MODEL_FILE_PATH` already establish. */
  KAFKA_AUDIT_TOPIC: z.string().min(1).default('manar.audit-events'),
  /** TLS to the brokers (`security.protocol` ssl, or sasl_ssl with SASL). */
  KAFKA_SSL: z.enum(['true', 'false']).optional(),
  /** PEM CA bundle for the brokers' certificates (librdkafka `ssl.ca.location`). */
  KAFKA_SSL_CA_FILE: z.string().min(1).optional(),
  /** SASL mechanism; with it, `KAFKA_SASL_USERNAME` and `KAFKA_SASL_PASSWORD` are required. */
  KAFKA_SASL_MECHANISM: z
    .enum(['plain', 'scram-sha-256', 'scram-sha-512'])
    .optional(),
  KAFKA_SASL_USERNAME: z.string().min(1).optional(),
  KAFKA_SASL_PASSWORD: z.string().min(1).optional(),
});

export type KafkaConfig = z.infer<typeof KafkaConfigSchema>;

/**
 * Constructor config for every Kafka client in this process (`KafkaJS.Kafka`). Throws on a
 * half-configured connection: a CA file without TLS, SASL without credentials, or PLAIN SASL
 * without TLS (it would send the password in clear).
 */
export function kafkaClientConfig(
  get: <K extends keyof KafkaConfig>(key: K) => KafkaConfig[K],
  clientId: string,
) {
  const brokers = get('KAFKA_BROKERS')
    .split(',')
    .map((broker) => broker.trim())
    .filter(Boolean);
  const ssl = get('KAFKA_SSL') === 'true';
  const caFile = get('KAFKA_SSL_CA_FILE');
  const mechanism = get('KAFKA_SASL_MECHANISM');
  const username = get('KAFKA_SASL_USERNAME');
  const password = get('KAFKA_SASL_PASSWORD');
  if (caFile && !ssl)
    throw new Error('KAFKA_SSL_CA_FILE is set but KAFKA_SSL is not true');
  if (mechanism && !(username && password))
    throw new Error(
      'KAFKA_SASL_MECHANISM needs KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD',
    );
  if (mechanism === 'plain' && !ssl)
    throw new Error('KAFKA_SASL_MECHANISM=plain needs KAFKA_SSL=true');
  return {
    kafkaJS: {
      brokers,
      clientId,
      ...(ssl ? { ssl: true } : {}),
      ...(mechanism && username && password
        ? { sasl: { mechanism, username, password } }
        : {}),
    },
    ...(caFile ? { 'ssl.ca.location': caFile } : {}),
  };
}
