import { z } from 'zod';

/** Same slug rules as manar-fleet; the slug is also the Keycloak realm name. */
export const CreatePlatformTenantSchema = z.object({
  slug: z.string().regex(/^[a-z][a-z0-9-]{1,38}[a-z0-9]$/),
  name: z.string().trim().min(1).max(200),
  residency: z.enum(['UAE', 'CUSTOM_REGION', 'AIR_GAPPED']).default('UAE'),
  /** Commercial or Government; unset is unknown. Government: AI off, recorded as an explicit choice. */
  sector: z.enum(['COMMERCIAL', 'GOVERNMENT']).optional(),
});

export type CreatePlatformTenant = z.infer<typeof CreatePlatformTenantSchema>;

/** Staff records the sector of a legacy workspace (api#62); more fields can join later. */
export const UpdatePlatformTenantSchema = z.object({
  sector: z.enum(['COMMERCIAL', 'GOVERNMENT']),
});

export type UpdatePlatformTenant = z.infer<typeof UpdatePlatformTenantSchema>;
