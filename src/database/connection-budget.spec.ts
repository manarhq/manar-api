import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { load } from 'js-yaml';
import { describe, expect, it } from 'vitest';

/** Postgres max_connections on the production server (docs/tenant-isolation.md, "Connection budget"). */
const SERVER_MAX_CONNECTIONS = 859;
/** The budget fails above this share of max_connections. */
const LIMIT_SHARE = 0.9;
/** Share of the tenant pool ceiling assumed busy at once (idle connections close after 10 s). */
const TENANT_SIMULTANEOUS_SHARE = 0.5;

/** Production overlay, manar-infra clusters/azure-uaenorth (no HPA exists): keep in step with it. */
const API_REPLICAS = 2;
const API_APPS_PER_POD = 2; // human HTTP and agent mTLS, each with its own pools
const WORKER_REPLICAS = 1;
const WORKER_APPS_PER_POD = 1;

/** Other consumers of the same server, at their configured maxima. */
const PGBOUNCER_DEFAULT_POOL_SIZE = 50; // the control pool goes through PgBouncer, capped here
const KEYCLOAK = 2 * 100; // replicas x Agroal max
const TEMPORAL = 4 * 2 * 20; // services x stores x maxConns
const OPENFGA = 2 * 30; // replicas x maxOpenConns
const SITE_FLEET = 3 * 10; // three services, one replica, pg default pool

interface Values {
  config: Record<string, string>;
}
const values = (chart: string) =>
  load(
    readFileSync(
      join(__dirname, '../../deploy/helm', chart, 'values.yaml'),
      'utf8',
    ),
  ) as Values;

const tenantCeiling = (c: Record<string, string>) =>
  Number(c.TENANT_DB_CLIENT_CACHE_MAX) * Number(c.DB_POOL_MAX_TENANT);

describe('Postgres connection budget', () => {
  it('every consumer, with tenant pools at their simultaneous share, stays within 90% of max_connections', () => {
    const tenant =
      API_REPLICAS *
        API_APPS_PER_POD *
        tenantCeiling(values('manar-api').config) +
      WORKER_REPLICAS *
        WORKER_APPS_PER_POD *
        tenantCeiling(values('manar-api-worker').config);
    const fixed =
      PGBOUNCER_DEFAULT_POOL_SIZE + KEYCLOAK + TEMPORAL + OPENFGA + SITE_FLEET;
    const total = tenant * TENANT_SIMULTANEOUS_SHARE + fixed;
    expect(total).toBeLessThanOrEqual(SERVER_MAX_CONNECTIONS * LIMIT_SHARE);
  });

  it('the control pool is smaller than the PgBouncer pool it shares', () => {
    for (const chart of ['manar-api', 'manar-api-worker']) {
      const per = Number(values(chart).config.DB_POOL_MAX_CONTROL);
      const pods =
        chart === 'manar-api'
          ? API_REPLICAS * API_APPS_PER_POD
          : WORKER_REPLICAS * WORKER_APPS_PER_POD;
      expect(per * pods).toBeLessThanOrEqual(PGBOUNCER_DEFAULT_POOL_SIZE);
    }
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
