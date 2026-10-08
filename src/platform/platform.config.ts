import { z } from 'zod';

/**
 * Service-to-service platform API for manar-fleet (ADR-0010). Off unless PLATFORM_API_ISSUER is
 * set: every /platform/v1 route then denies. Tokens come from a client-credentials client in the
 * platform (master) realm whose service account holds PLATFORM_API_ROLE.
 */
export const PlatformConfigSchema = z.object({
  /** Exact issuer of platform tokens, e.g. http://localhost:8081/realms/master. */
  PLATFORM_API_ISSUER: z.preprocess(
    (v) => (typeof v === 'string' && v.trim() ? v.trim() : undefined),
    z.string().optional(),
  ),
  PLATFORM_API_CLIENT_ID: z.string().min(1).default('manar-fleet'),
  PLATFORM_API_ROLE: z.string().min(1).default('manar-platform-admin'),
});

export type PlatformConfig = z.infer<typeof PlatformConfigSchema>;
