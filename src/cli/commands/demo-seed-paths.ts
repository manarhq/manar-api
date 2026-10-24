/** The shared demo tenant: its files are the rehearsed fallback's (scripts/demo-agent.ts). */
export const DEMO_TENANT_SLUG = 'vax-security-ops-demo';

/**
 * Where demo:seed writes the tenant credentials and agent identities. The
 * demo tenant keeps `.manar-demo/`; any other tenant (MANAR_SEED_TENANT_SLUG,
 * e.g. a load-test tenant) gets `.manar-demo/<slug>/`, so seeding it never
 * overwrites the demo's credentials or identities.
 */
export function seedPaths(tenantSlug: string): {
  credentials: string;
  identity: (agentSlug: string) => string;
} {
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(tenantSlug)) {
    throw new Error(`Invalid tenant slug "${tenantSlug}"`);
  }
  const dir =
    tenantSlug === DEMO_TENANT_SLUG
      ? '.manar-demo'
      : `.manar-demo/${tenantSlug}`;
  return {
    credentials: `${dir}/tenant-credentials.json`,
    identity: (agentSlug) => `${dir}/identities/${agentSlug}.identity`,
  };
}
