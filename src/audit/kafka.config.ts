import { z } from 'zod';
import { unreadableFile } from './live/redis.config';

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
 * Cross-field rules, checked at startup (`AppConfigSchema`, so a bad value stops the process
 * instead of leaving the best-effort consumers silently disconnected) and by
 * `kafkaClientConfig`. SASL only over TLS, mechanism and credentials together, a readable CA
 * only with TLS.
 */
export function kafkaConfigIssues(c: Partial<KafkaConfig>): string[] {
  const ssl = c.KAFKA_SSL === 'true';
  const creds = Boolean(c.KAFKA_SASL_USERNAME || c.KAFKA_SASL_PASSWORD);
  const issues: string[] = [];
  if (c.KAFKA_SSL_CA_FILE && !ssl)
    issues.push('KAFKA_SSL_CA_FILE is set but KAFKA_SSL is not true');
  if (unreadableFile(c.KAFKA_SSL_CA_FILE))
    issues.push('KAFKA_SSL_CA_FILE cannot be read');
  if (
    c.KAFKA_SASL_MECHANISM &&
    !(c.KAFKA_SASL_USERNAME && c.KAFKA_SASL_PASSWORD)
  )
    issues.push(
      'KAFKA_SASL_MECHANISM needs KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD',
    );
  if (creds && !c.KAFKA_SASL_MECHANISM)
    issues.push(
      'KAFKA_SASL_USERNAME or KAFKA_SASL_PASSWORD is set without KAFKA_SASL_MECHANISM',
    );
  if ((c.KAFKA_SASL_MECHANISM || creds) && !ssl)
    issues.push(
      'Kafka SASL needs KAFKA_SSL=true (credentials would cross the network in clear)',
    );
  return issues;
}

/** Constructor config for every Kafka client in this process (`KafkaJS.Kafka`); throws on a misconfiguration. */
export function kafkaClientConfig(
  get: <K extends keyof KafkaConfig>(key: K) => KafkaConfig[K],
  clientId: string,
) {
  const c: Partial<KafkaConfig> = {
    KAFKA_BROKERS: get('KAFKA_BROKERS'),
    KAFKA_SSL: get('KAFKA_SSL'),
    KAFKA_SSL_CA_FILE: get('KAFKA_SSL_CA_FILE'),
    KAFKA_SASL_MECHANISM: get('KAFKA_SASL_MECHANISM'),
    KAFKA_SASL_USERNAME: get('KAFKA_SASL_USERNAME'),
    KAFKA_SASL_PASSWORD: get('KAFKA_SASL_PASSWORD'),
  };
  const [issue] = kafkaConfigIssues(c);
  if (issue) throw new Error(issue);
  const brokers = (c.KAFKA_BROKERS ?? '')
    .split(',')
    .map((broker) => broker.trim())
    .filter(Boolean);
  const mechanism = c.KAFKA_SASL_MECHANISM;
  const username = c.KAFKA_SASL_USERNAME;
  const password = c.KAFKA_SASL_PASSWORD;
  return {
    kafkaJS: {
      brokers,
      clientId,
      ...(c.KAFKA_SSL === 'true' ? { ssl: true } : {}),
      ...(mechanism && username && password
        ? { sasl: { mechanism, username, password } }
        : {}),
    },
    ...(c.KAFKA_SSL_CA_FILE ? { 'ssl.ca.location': c.KAFKA_SSL_CA_FILE } : {}),
  };
}
