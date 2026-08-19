import type { AppConfig } from '../config/env.validation';

/**
 * Turns `CORS_ALLOWED_ORIGINS` (a raw comma-separated string, or `*`) into
 * `@nestjs/platform-fastify`'s `enableCors({ origin })` option.
 *
 * Section 99's hard rule: `NODE_ENV === 'production'` with a wildcard (`*`,
 * or unset) throws at boot rather than silently falling back to something
 * safe — a production deployment that forgets to configure this explicitly
 * must fail to start, not quietly run wide open. Outside production, `*`
 * is honored as `origin: true` (reflects the request's own `Origin`
 * header) for local-dev convenience.
 */
export function resolveCorsOrigin(
  config: Pick<AppConfig, 'CORS_ALLOWED_ORIGINS' | 'NODE_ENV'>,
): boolean | string[] {
  const raw = config.CORS_ALLOWED_ORIGINS.trim();
  const isWildcard = raw === '*' || raw.length === 0;

  if (config.NODE_ENV === 'production' && isWildcard) {
    throw new Error(
      'CORS_ALLOWED_ORIGINS must be set to an explicit, comma-separated allow-list in production — a wildcard ("*") origin is never permitted (Section 99).',
    );
  }

  if (isWildcard) return true;

  return raw
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}
