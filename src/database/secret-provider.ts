/**
 * The single swap point for how a tenant's database credential is
 * resolved. `EnvSecretProvider` (this phase's only implementation) reads a
 * base connection URL from a named environment variable.
 * `OpenBaoSecretProvider` (Phase 4/17) will implement the same interface
 * against a real secret store — no caller changes when it arrives. See
 * docs/tenant-isolation.md.
 */
export interface SecretReferenceDescriptor {
  provider: 'ENV' | 'OPENBAO';
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
