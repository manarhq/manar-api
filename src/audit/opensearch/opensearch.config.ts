import { z } from 'zod';

/**
 * Phase 9b (OpenSearch Indexing) — connection settings for
 * `OpenSearchIndexService`. Read by whichever process indexes/reindexes
 * `AuditEvent`s: the main HTTP process (`AuditIndexerService`'s live Kafka
 * consumer — see `docs/audit-chain.md`) and the CLI's `audit:reindex`
 * command (`src/cli/commands/audit-reindex.command.ts`).
 */
export const OpenSearchConfigSchema = z.object({
  /**
   * Matches `deploy/docker-compose.yml`'s `opensearch` service's
   * host-mapped REST API port — every process that reads this config runs
   * on the host, never inside the compose network.
   */
  OPENSEARCH_NODE: z.string().min(1).default('http://localhost:9200'),
  /**
   * A single, tenant-tagged index (every document carries `tenantId`)
   * rather than one index per tenant — simpler to reindex/query for this
   * phase's MVP scope ("no OpenSearch sharding/lifecycle policies beyond a
   * sane default" is explicitly out of scope). See `docs/audit-chain.md`.
   */
  OPENSEARCH_AUDIT_INDEX: z.string().min(1).default('manar-audit-events'),
});

export type OpenSearchConfig = z.infer<typeof OpenSearchConfigSchema>;
