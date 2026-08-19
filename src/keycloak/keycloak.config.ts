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

  /**
   * Phase 14 security cleanup 2: `manar-web`'s own base URL, used to
   * register its OIDC callback (`<MANAR_WEB_BASE_URL>/api/auth/callback`)
   * and origin as the confidential client's `redirectUris`/`webOrigins`
   * at tenant-provisioning time (`TenantProvisioningService`), instead of
   * `manar-web`'s BFF registering it itself, lazily, on the first login
   * attempt against a given realm.
   *
   * That lazy registration (`manar-web/lib/auth/keycloak-admin.ts`'s
   * `ensureRedirectUriRegistered`, called from `/api/auth/login`) is why
   * `manar-web` still held standing `KEYCLOAK_ADMIN_USERNAME`/`PASSWORD`
   * credentials after Phase 11b Part 1 closed the sibling client-*secret*
   * workaround — reading that code confirmed the redirect URI it registers
   * is always the *same*, deployment-wide value
   * (`new URL("/api/auth/callback", env.APP_BASE_URL)`, `APP_BASE_URL`
   * being a fixed env var, never derived per-tenant or per-login), so
   * there is no reason it needs to be discovered lazily by a
   * browser-facing process at all — it's exactly the kind of static,
   * known-at-provisioning-time value `TenantProvisioningService` already
   * seeds every other one-time realm/role/client setting for. Registering
   * it here removes `manar-web`'s need for Keycloak admin credentials
   * entirely (Part 2, `manar-web`, removes the now-dead
   * `ensureRedirectUriRegistered`/`KEYCLOAK_ADMIN_*` code — out of scope
   * for `manar-api`).
   *
   * No trailing slash. Matches `manar-web`'s own `APP_BASE_URL` default
   * for local dev.
   */
  MANAR_WEB_BASE_URL: z.string().min(1).default('http://localhost:3100'),
});

export type KeycloakConfig = z.infer<typeof KeycloakConfigSchema>;
