import { describe, expect, it } from 'vitest';
import { DEMO_TENANT_SLUG, seedPaths } from './demo-seed-paths';

describe('seedPaths', () => {
  it('keeps the demo tenant on the paths the rehearsed fallback reads', () => {
    const p = seedPaths(DEMO_TENANT_SLUG);
    expect(p.credentials).toBe('.manar-demo/tenant-credentials.json');
    expect(p.identity('soc-response-agent')).toBe(
      '.manar-demo/identities/soc-response-agent.identity',
    );
  });

  it('gives any other tenant its own directory, so the demo files are never overwritten', () => {
    const p = seedPaths('p3-load');
    expect(p.credentials).toBe('.manar-demo/p3-load/tenant-credentials.json');
    expect(p.identity('soc-response-agent')).toBe(
      '.manar-demo/p3-load/identities/soc-response-agent.identity',
    );
  });

  it('refuses a slug that could escape the directory', () => {
    expect(() => seedPaths('../etc')).toThrow();
  });
});
