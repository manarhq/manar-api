import { readFileSync } from 'node:fs';
import { unreadableFile } from '../live/redis.config';
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
 * Cross-field rules, checked at startup (`AppConfigSchema`) and by `openSearchClientOptions`:
 * both credentials or neither, credentials (here or in the node URL) only over `https://`, and a
 * CA file only for `https://` and readable.
 */
export function openSearchConfigIssues(c: Partial<OpenSearchConfig>): string[] {
  const node = c.OPENSEARCH_NODE ?? '';
  const https = node.startsWith('https://');
  let urlCredentials = false;
  try {
    const u = new URL(node);
    urlCredentials = Boolean(u.username || u.password);
  } catch {
    // An unparsable node fails in the client; nothing to add here.
  }
  const issues: string[] = [];
  if (Boolean(c.OPENSEARCH_USERNAME) !== Boolean(c.OPENSEARCH_PASSWORD))
    issues.push(
      'Set both OPENSEARCH_USERNAME and OPENSEARCH_PASSWORD, or neither',
    );
  if (
    (c.OPENSEARCH_USERNAME || c.OPENSEARCH_PASSWORD || urlCredentials) &&
    !https
  )
    issues.push(
      'OpenSearch credentials need an https:// OPENSEARCH_NODE (they would be sent in clear)',
    );
  if (c.OPENSEARCH_TLS_CA_FILE && !https)
    issues.push(
      'OPENSEARCH_TLS_CA_FILE is set but OPENSEARCH_NODE is not https://',
    );
  if (unreadableFile(c.OPENSEARCH_TLS_CA_FILE))
    issues.push('OPENSEARCH_TLS_CA_FILE cannot be read');
  return issues;
}

/** Client options for `OPENSEARCH_NODE`; a misconfigured connection throws. */
export function openSearchClientOptions(
  get: <K extends keyof OpenSearchConfig>(key: K) => OpenSearchConfig[K],
) {
  const c: Partial<OpenSearchConfig> = {
    OPENSEARCH_NODE: get('OPENSEARCH_NODE'),
    OPENSEARCH_USERNAME: get('OPENSEARCH_USERNAME'),
    OPENSEARCH_PASSWORD: get('OPENSEARCH_PASSWORD'),
    OPENSEARCH_TLS_CA_FILE: get('OPENSEARCH_TLS_CA_FILE'),
  };
  const [issue] = openSearchConfigIssues(c);
  if (issue) throw new Error(issue);
  const { OPENSEARCH_USERNAME: username, OPENSEARCH_PASSWORD: password } = c;
  const caFile = c.OPENSEARCH_TLS_CA_FILE;
  return {
    node: c.OPENSEARCH_NODE as string,
    ...(username && password ? { auth: { username, password } } : {}),
    ...(caFile ? { ssl: { ca: readFileSync(caFile) } } : {}),
  };
}
