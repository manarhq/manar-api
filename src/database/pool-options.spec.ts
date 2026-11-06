import { describe, expect, it } from 'vitest';
import { pgPoolOptions, poolSettings } from './pool-options';

describe('pool options', () => {
  const cfg: Record<string, number> = {
    DB_POOL_MAX_CONTROL: 7,
    DB_POOL_MAX_TENANT: 3,
    DB_POOL_CONNECT_TIMEOUT_MS: 1234,
    DB_QUERY_TIMEOUT_MS: 9999,
    DB_STATEMENT_TIMEOUT_MS: 4321,
  };
  const get = (k: string) => cfg[k];

  it('tenant pools are bounded and carry the server-side statement timeout', () => {
    expect(pgPoolOptions('postgres://x', poolSettings(get, 'tenant'))).toEqual({
      connectionString: 'postgres://x',
      max: 3,
      connectionTimeoutMillis: 1234,
      query_timeout: 9999,
      statement_timeout: 4321,
    });
  });

  it('the control pool is bounded and sends the statement timeout too (its URL is direct)', () => {
    const o = pgPoolOptions('postgres://x', poolSettings(get, 'control'));
    expect(o.max).toBe(7);
    expect(o.statement_timeout).toBe(4321);
  });

  it('falls back to the schema defaults for a partial config', () => {
    expect(poolSettings(() => undefined, 'tenant')).toMatchObject({
      max: 3,
      connectTimeoutMs: 3000,
      statementTimeoutMs: 30_000,
    });
  });
});
