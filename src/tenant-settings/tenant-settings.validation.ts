import { z } from 'zod';

const TENANT_RESIDENCY_VALUES = ['UAE', 'CUSTOM_REGION', 'AIR_GAPPED'] as const;

/**
 * `PATCH /tenant/settings`'s request body — every field optional (a
 * partial update), but at least one must be present (an empty PATCH is
 * almost certainly a caller bug, not a legitimate no-op request). Only the
 * four `Tenant` columns that have existed since Phase 2
 * (`docs/superpowers/specs/2026-08-18-phase2-tenant-provisioning-design.md`)
 * are writable here — see `TenantSettingsService`'s doc comment for why
 * `sso`/`aiProvider`/`rateLimit` (also surfaced by `GET /tenant/settings`)
 * are read-only.
 */
export const UpdateTenantSettingsSchema = z
  .object({
    residency: z.enum(TENANT_RESIDENCY_VALUES).optional(),
    allowExternalAi: z.boolean().optional(),
    allowOutboundTelemetry: z.boolean().optional(),
    allowCloudStorage: z.boolean().optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: 'At least one field must be provided',
  });
export type UpdateTenantSettingsRequest = z.infer<
  typeof UpdateTenantSettingsSchema
>;
