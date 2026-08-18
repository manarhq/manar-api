import { z } from 'zod';

/**
 * Environment schema for this service, mirroring manar-api's own
 * Zod-validated-env convention (see `src/config/env.validation.ts` in the
 * repo root) even though this is a plain Fastify service rather than a
 * Nest one — same "fail fast with one itemized error list" contract,
 * just invoked directly from `main.ts` instead of through
 * `@nestjs/config`'s `validate()` extension point.
 */
export const DemoSocToolsConfigSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(3100),
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
  LOG_LEVEL: z
    .enum(['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'])
    .default('info'),
  /**
   * Single static bearer token every `/v1/*` request must present
   * (`Authorization: Bearer <token>`). Deliberately simple — this is the
   * credential Phase 7b's `CredentialBrokerService` fetches from OpenBao
   * and injects; no agent ever sees it directly. No default: an unset key
   * would make every write endpoint silently unauthenticated, so this
   * fails startup instead.
   */
  DEMO_TOOLS_API_KEY: z.string().min(1, 'DEMO_TOOLS_API_KEY is required'),
});

export type DemoSocToolsConfig = z.infer<typeof DemoSocToolsConfigSchema>;

/**
 * Validates `process.env` (or an equivalent record) against
 * `DemoSocToolsConfigSchema`. Throws a single, readable, itemized error
 * if anything is missing or invalid so the process fails fast at boot
 * instead of starting into a bad state.
 */
export function validate(env: Record<string, unknown>): DemoSocToolsConfig {
  const result = DemoSocToolsConfigSchema.safeParse(env);

  if (!result.success) {
    const issues = result.error.issues
      .map(
        (issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`,
      )
      .join('\n');

    throw new Error(
      `Invalid environment configuration. Fix the following and restart:\n${issues}`,
    );
  }

  return result.data;
}
