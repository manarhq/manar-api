/**
 * The single swap point for how a secret (a tenant database credential, or
 * — since Phase 7b — a `Tool.credentialReference`) is resolved.
 * `EnvSecretProvider` reads a value from a named environment variable;
 * `OpenBaoSecretProvider` (Phase 7b, `src/database/openbao-secret-provider.ts`)
 * reads one from OpenBao's KV v2 secrets engine. `DatabaseModule` binds the
 * `SECRET_PROVIDER` token to `CompositeSecretProvider`
 * (`src/database/composite-secret-provider.ts`), which dispatches to
 * whichever concrete provider a given reference's `provider` field
 * actually names — a caller holding a `SecretProvider` never needs to know
 * or care which backend answered `resolve()`. See docs/tenant-isolation.md
 * and docs/tool-gateway.md.
 */
export interface SecretReferenceDescriptor {
  /**
   * `CONTROL_DB` (Phase 3) is a valid `SecretReference.provider` value —
   * see `prisma/control.prisma`'s `SecretProvider` enum doc — but is
   * resolved directly by callers that read `SecretReference.reference` as
   * a literal value (e.g. `TenantProvisioningService`'s Keycloak client
   * secret), never through `SecretProvider.resolve()`/`EnvSecretProvider`,
   * which only implements `ENV` this phase and throws for anything else.
   * Included in this union so the type accepts every value the Prisma
   * `SecretProvider` enum can produce.
   */
  provider: 'ENV' | 'OPENBAO' | 'CONTROL_DB';
  reference: string;
}

export interface SecretProvider {
  resolve(ref: SecretReferenceDescriptor): Promise<string>;
}

/** DI token — `SecretProvider` is an interface, not a class, so it can't be used as one. */
export const SECRET_PROVIDER = Symbol('SECRET_PROVIDER');

/**
 * Default env var name `provisionTenant` records in
 * `SecretReference.reference` for the `ENV` provider. The `SecretReference`
 * schema stores this as an opaque string per tenant so a future provider
 * swap or per-tenant override never requires a schema change — this
 * constant is just this phase's convention for what goes in it.
 */
export const DEFAULT_TENANT_DB_SECRET_REFERENCE = 'TENANT_DB_BASE_URL';
