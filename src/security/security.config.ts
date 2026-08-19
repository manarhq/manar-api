import { z } from 'zod';

/**
 * Phase 12a (security headers & CORS). `CORS_ALLOWED_ORIGINS` is a
 * comma-separated allow-list — see `parseAllowedOrigins` below for how it's
 * turned into `@nestjs/platform-fastify`'s `enableCors` origin option.
 *
 * **Section 99's explicit hard rule: no wildcard origin in production.**
 * `'*'` is accepted in the raw string only because a developer's local
 * `.env` may reasonably want it for convenience — `resolveCorsOrigin`
 * (`src/security/cors.ts`) is the one place that actually enforces the
 * production restriction, refusing to boot with a wildcard when
 * `NODE_ENV === 'production'` rather than silently downgrading it to
 * something safe (Section 99 asks for a hard rule, not a best-effort one).
 */
export const SecurityConfigSchema = z.object({
  /**
   * Comma-separated list of allowed CORS origins (e.g.
   * `https://app.example.com,https://admin.example.com`), or the single
   * literal `*` for local development only. Defaults to `*` — safe as a
   * *default* only because `resolveCorsOrigin` refuses to honor it once
   * `NODE_ENV=production`, forcing every real deployment to set this
   * explicitly.
   */
  CORS_ALLOWED_ORIGINS: z.string().min(1).default('*'),
});

export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;
