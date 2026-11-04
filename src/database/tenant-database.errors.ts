/**
 * Thrown by `TenantDatabaseManager.resolveTenant`/`getClient` when a tenant
 * ID does not resolve to an active tenant with a provisioned database
 * binding — including unknown IDs and deprovisioned/deleted tenants. Never
 * silently falls back to the control DB or another tenant (fail closed).
 */
export class TenantNotFoundError extends Error {
  constructor(tenantId: string) {
    super(
      `Tenant "${tenantId}" was not found or has no active database binding`,
    );
    this.name = 'TenantNotFoundError';
  }
}

/** Thrown by `provisionTenant` when the requested slug already exists. */
export class TenantSlugConflictError extends Error {
  constructor(slug: string) {
    super(`A tenant with slug "${slug}" already exists`);
    this.name = 'TenantSlugConflictError';
  }
}

/** Thrown by `provisionTenant` when the creator already made `max` workspaces of this kind. Nothing is written. */
export class TenantCreatorLimitError extends Error {
  constructor(public readonly max: number) {
    super(
      `The creator has reached the limit of ${max} workspaces of this kind`,
    );
    this.name = 'TenantCreatorLimitError';
  }
}

/**
 * Thrown by `provisionTenant` when database creation or the tenant schema
 * migration fails after the control-DB rows were created. The tenant is
 * left in `PROVISIONING` status for manual inspection/retry — this phase
 * does not implement automatic rollback (out of scope; see
 * docs/tenant-isolation.md).
 */
export class TenantProvisioningError extends Error {
  constructor(slug: string, cause: unknown) {
    super(
      `Failed to provision tenant "${slug}": ${cause instanceof Error ? cause.message : String(cause)}`,
    );
    this.name = 'TenantProvisioningError';
    this.cause = cause;
  }
}

/** A lifecycle change found the tenant in another state than the one it requires. */
export class TenantLifecycleConflictError extends Error {
  constructor(tenantId: string, expectedStatus: string) {
    super(`Tenant "${tenantId}" is not ${expectedStatus}`);
    this.name = 'TenantLifecycleConflictError';
  }
}
