import { z } from 'zod';

/**
 * Keycloak-related environment schema, kept alongside the `keycloak` module
 * rather than growing `AppConfigSchema` into a god-schema (see
 * `src/config/env.validation.ts` and `src/database/database.config.ts` for
 * the established pattern). Merged into the single root `validate()`
 * function so startup still fails fast with one itemized error list.
 *
 * These are deployment-wide settings (one Keycloak server, one bootstrap
 * admin), not per-tenant secrets — per-tenant secrets (each realm's
 * `manar-api` client secret) are generated at provisioning time and stored
 * as a `SecretReference` row in the control DB instead (see
 * `src/keycloak/keycloak-client-secret.store.ts`), because a static env var
 * name can't name a value that doesn't exist until a tenant is provisioned.
 */
export const KeycloakConfigSchema = z.object({
  /** Base URL of the Keycloak server, no trailing slash (e.g. http://localhost:8081). */
  KEYCLOAK_BASE_URL: z.string().min(1, 'KEYCLOAK_BASE_URL is required'),

  /**
   * Bootstrap admin credentials for the Keycloak *master* realm, used only
   * by server-side provisioning code (TenantProvisioningService) to call
   * the Admin REST API. Never forwarded to clients, never logged — see
   * `src/keycloak/keycloak-admin.client.ts`.
   */
  KEYCLOAK_ADMIN_USERNAME: z
    .string()
    .min(1, 'KEYCLOAK_ADMIN_USERNAME is required'),
  KEYCLOAK_ADMIN_PASSWORD: z
    .string()
    .min(1, 'KEYCLOAK_ADMIN_PASSWORD is required'),

  /** Client used to authenticate the bootstrap admin against the master realm. */
  KEYCLOAK_ADMIN_CLIENT_ID: z.string().min(1).default('admin-cli'),

  /**
   * `clientId` (not the Keycloak-internal UUID) of the confidential client
   * TenantProvisioningService creates in every tenant realm for manar-api
   * to authenticate against / validate tokens for.
   */
  KEYCLOAK_CLIENT_ID: z.string().min(1).default('manar-api'),
});

export type KeycloakConfig = z.infer<typeof KeycloakConfigSchema>;
