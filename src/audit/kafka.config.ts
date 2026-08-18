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
});

export type KafkaConfig = z.infer<typeof KafkaConfigSchema>;
