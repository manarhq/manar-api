import { readFileSync } from 'node:fs';
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
  /** Basic-auth user and password for a secured cluster. */
  OPENSEARCH_USERNAME: z.string().min(1).optional(),
  OPENSEARCH_PASSWORD: z.string().min(1).optional(),
  /** PEM CA bundle for an `https://` node whose certificate is not from a public CA. */
  OPENSEARCH_TLS_CA_FILE: z.string().min(1).optional(),
});

export type OpenSearchConfig = z.infer<typeof OpenSearchConfigSchema>;

/**
 * Client options for `OPENSEARCH_NODE`: basic auth when both credentials are set, the CA when
 * given. Half a credential pair, or a CA file for a plain `http://` node, throws.
 */
export function openSearchClientOptions(
  get: <K extends keyof OpenSearchConfig>(key: K) => OpenSearchConfig[K],
) {
  const node = get('OPENSEARCH_NODE');
  const username = get('OPENSEARCH_USERNAME');
  const password = get('OPENSEARCH_PASSWORD');
  const caFile = get('OPENSEARCH_TLS_CA_FILE');
  if (Boolean(username) !== Boolean(password))
    throw new Error(
      'Set both OPENSEARCH_USERNAME and OPENSEARCH_PASSWORD, or neither',
    );
  if (caFile && !node.startsWith('https://'))
    throw new Error(
      'OPENSEARCH_TLS_CA_FILE is set but OPENSEARCH_NODE is not https://',
    );
  return {
    node,
    ...(username && password ? { auth: { username, password } } : {}),
    ...(caFile ? { ssl: { ca: readFileSync(caFile) } } : {}),
  };
}
