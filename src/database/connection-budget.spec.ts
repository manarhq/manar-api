import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { load } from 'js-yaml';
import { describe, expect, it } from 'vitest';

/** Postgres max_connections on the production server (docs/tenant-isolation.md). */
const SERVER_MAX_CONNECTIONS = 859;
const BUDGET_SHARE = 0.6;
/** The api HPA lives in the infra repo; keep this equal to its maxReplicas. */
const API_MAX_REPLICAS = 4;
/** The api pod runs two Nest apps (human HTTP and agent mTLS), each with its own pools. */
const API_APPS_PER_POD = 2;

interface Values {
  replicaCount: number;
  config: Record<string, string>;
}
const values = (chart: string) =>
  load(
    readFileSync(
      join(__dirname, '../../deploy/helm', chart, 'values.yaml'),
      'utf8',
    ),
  ) as Values;

const perApp = (c: Record<string, string>) =>
  Number(c.DB_POOL_MAX_CONTROL) +
  Number(c.TENANT_DB_CLIENT_CACHE_MAX) * Number(c.DB_POOL_MAX_TENANT);

describe('Postgres connection budget', () => {
  it('pool sizes x replicas stay within 60% of the server max_connections', () => {
    const api = values('manar-api');
    const worker = values('manar-api-worker');
    const total =
      API_APPS_PER_POD * API_MAX_REPLICAS * perApp(api.config) +
      worker.replicaCount * perApp(worker.config);
    expect(total).toBeLessThanOrEqual(SERVER_MAX_CONNECTIONS * BUDGET_SHARE);
  });

  it('the client query timeout stays above the server statement timeout', () => {
    for (const chart of ['manar-api', 'manar-api-worker']) {
      const c = values(chart).config;
      expect(Number(c.DB_QUERY_TIMEOUT_MS)).toBeGreaterThan(
        Number(c.DB_STATEMENT_TIMEOUT_MS),
      );
    }
  });
});
