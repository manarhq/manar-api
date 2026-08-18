import { z } from 'zod';

/**
 * OpenFGA-related environment schema (Phase 5: Tasks, Delegation &
 * OpenFGA), kept alongside the `authorization` module rather than growing
 * `AppConfigSchema` into a god-schema — see `src/config/env.validation.ts`
 * and `src/openbao/openbao.config.ts` for the established pattern.
 *
 * Unlike OpenBao (Phase 4), there is no separate init script this phase:
 * `OpenFgaBootstrapService.onModuleInit` resolves-or-creates the store and
 * writes-or-reuses the authorization model itself, at application boot,
 * every time. This is a deliberate difference from OpenBao's CA bootstrap
 * (which genuinely can't be automatic — CA generation is destructive if
 * re-run, so it's a separate, manually-invoked, idempotency-guarded
 * script): a store/model resolution has no such hazard (creating a model
 * version is purely additive; OpenFGA keeps every version), so there is no
 * reason to make an operator run a second command and copy a generated ID
 * into `.env` by hand. `OPENFGA_STORE_ID`/`OPENFGA_AUTHORIZATION_MODEL_ID`
 * below are still real config fields (the "existing typed-config pattern"
 * the design spec asks for) — set them to pin a specific store/model
 * explicitly (e.g. a production deployment that provisions its OpenFGA
 * store out-of-band and never wants this process auto-creating one);
 * leave them unset (the default) for local dev/CI, where auto-resolution
 * by well-known store name is exactly what's wanted.
 */
export const OpenFgaConfigSchema = z.object({
  /** Base URL of the OpenFGA HTTP API, no trailing slash (e.g. http://localhost:8080). */
  OPENFGA_API_URL: z.string().min(1).default('http://localhost:8080'),

  /**
   * Store name `OpenFgaBootstrapService` looks for (via `listStores`) or
   * creates if none exists yet, when `OPENFGA_STORE_ID` is not set. Stores
   * are cheap and namespaced by name only by convention (OpenFGA itself
   * doesn't enforce unique store names) — this is deployment-wide, not
   * per-tenant, matching how this is a single shared relationship-
   * authorization engine across every tenant (see
   * docs/authorization-model.md's "known limitation" on tenant scoping).
   */
  OPENFGA_STORE_NAME: z.string().min(1).default('manar'),

  /** Pins a specific store ID, skipping name-based discovery/creation entirely. */
  OPENFGA_STORE_ID: z.string().min(1).optional(),

  /** Pins a specific authorization model ID, skipping the DSL-diff-and-write-if-changed logic entirely. */
  OPENFGA_AUTHORIZATION_MODEL_ID: z.string().min(1).optional(),

  /** Path to the DSL model file transformed into JSON at boot — see src/authorization/model/manar.fga. */
  OPENFGA_MODEL_FILE_PATH: z
    .string()
    .min(1)
    .default('src/authorization/model/manar.fga'),
});

export type OpenFgaConfig = z.infer<typeof OpenFgaConfigSchema>;
