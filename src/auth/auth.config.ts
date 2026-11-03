import { z } from 'zod';

/**
 * Human-token trust and workspace settings (spec 4.1, 4.2, 7a). Every key is optional so existing
 * deployments and test fixtures keep validating; `authSetting` supplies the defaults.
 */
export const AuthConfigSchema = z.object({
  /**
   * Comma-separated issuer URLs whose tokens this API accepts: the shared hosted realm
   * (`https://auth-manar.fixio.ae/realms/manar`) and, for a customer-hosted install, that install's
   * realm. A legacy per-tenant realm recorded in `Tenant.keycloakIssuerUrl` is accepted too and is
   * bound to its tenant. Anything else is rejected.
   */
  AUTH_ISSUERS: z.string().optional(),
  /** Company trial start (Entra admin only). Off switch per the spec 5 slip rule. */
  COMPANY_TRIAL_ENABLED: z.enum(['true', 'false']).optional(),
  /** Sign-ups queue once this many workspaces are being provisioned at once (default 4)... */
  WORKSPACE_PROVISION_CONCURRENCY: z.coerce.number().int().min(1).optional(),
  /** ...or once this many tenant databases exist (default 5000) times the ratio below. */
  WORKSPACE_MAX_TENANTS: z.coerce.number().int().min(1).optional(),
  /** Default 0.95; a warning is logged from 70%. */
  WORKSPACE_QUEUE_AT_RATIO: z.coerce.number().min(0.1).max(1).optional(),
  /** Queue drain period in ms (default 5000); 0 turns the loop off (the CLI still drains). */
  WORKSPACE_QUEUE_DRAIN_MS: z.coerce.number().int().min(0).optional(),
  /** New workspaces (each a database) the deployment creates per hour, all accounts together (default 120). */
  WORKSPACE_CREATE_PER_HOUR: z.coerce.number().int().min(1).optional(),
  /** Bounded concurrency for `tenants:migrate` (default 4). */
  TENANT_MIGRATE_CONCURRENCY: z.coerce.number().int().min(1).max(32).optional(),
});

export const AUTH_DEFAULTS = {
  COMPANY_TRIAL_ENABLED: 'true',
  WORKSPACE_PROVISION_CONCURRENCY: 4,
  WORKSPACE_MAX_TENANTS: 5000,
  WORKSPACE_QUEUE_AT_RATIO: 0.95,
  WORKSPACE_QUEUE_DRAIN_MS: 5000,
  WORKSPACE_CREATE_PER_HOUR: 120,
  TENANT_MIGRATE_CONCURRENCY: 4,
} as const;

type Defaults = typeof AUTH_DEFAULTS;

/** Reads one setting from a ConfigService-like object, with its default. */
export function authSetting<K extends keyof Defaults>(
  config: { get(key: K, opts: { infer: true }): unknown },
  key: K,
): Defaults[K] extends number ? number : string {
  const v = config.get(key, { infer: true });
  return (v ?? AUTH_DEFAULTS[key]) as never;
}
