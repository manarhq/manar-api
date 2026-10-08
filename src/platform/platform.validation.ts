import { z } from 'zod';

/** Same slug rules as manar-fleet; the slug is also the Keycloak realm name. */
export const CreatePlatformTenantSchema = z.object({
  slug: z.string().regex(/^[a-z][a-z0-9-]{1,38}[a-z0-9]$/),
  name: z.string().trim().min(1).max(200),
  residency: z.enum(['UAE', 'CUSTOM_REGION', 'AIR_GAPPED']).default('UAE'),
});

export type CreatePlatformTenant = z.infer<typeof CreatePlatformTenantSchema>;
