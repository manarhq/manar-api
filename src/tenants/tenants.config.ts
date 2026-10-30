import { z } from 'zod';

/**
 * Phase 11b Part 1 — config for the `GET /tenants/:slug/oidc-client-secret`
 * BFF-only endpoint (see `tenants.controller.ts`'s
 * own doc comments for the full design rationale).
 *
 * `MANAR_BFF_SERVICE_TOKEN` is a **narrow, single-purpose** shared secret
 * between `manar-api` and `manar-web`'s BFF — never a copy of, or
 * equivalent in privilege to, `KEYCLOAK_ADMIN_USERNAME`/`PASSWORD`
 * (Section 11's infrastructure-operator credential, which this endpoint
 * exists specifically so `manar-web` never needs its own copy of — see
 * `manar-web/docs/auth-flow.md`'s "Known limitation: client secret
 * retrieval"). Possessing this token only ever unlocks "read back one
 * already-provisioned tenant's already-generated OIDC client secret" —
 * never realm creation, role management, or any other Keycloak Admin API
 * capability. Same "separate, non-tenant-scoped operator credential"
 * shape `PLATFORM_KILL_SWITCH_OPERATOR_TOKEN` already establishes in this
 * codebase (`src/kill-switches/kill-switches.config.ts`) — reused here
 * for the identical reason: a capability this sensitive must never be
 * gated by *only* a per-tenant JWT role (there is no tenant JWT at all at
 * this point in the login flow — this endpoint is necessarily called
 * pre-login).
 */
/** Unused since the client-secret endpoint was retired (spec 4.1); kept optional so existing deployments still start. */
export const TenantsConfigSchema = z.object({
  /**
   * No production default — the `.env`/`.env.example` dev value is only
   * ever a placeholder, same posture as this codebase's other dev-only
   * shared secrets (`PLATFORM_KILL_SWITCH_OPERATOR_TOKEN`,
   * `APPROVAL_GRANT_SIGNING_SECRET`).
   */
  MANAR_BFF_SERVICE_TOKEN: z.string().min(16).optional(),
});

export type TenantsConfig = z.infer<typeof TenantsConfigSchema>;
