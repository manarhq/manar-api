import { SetMetadata } from '@nestjs/common';
import type { RoleName } from './roles';

export const REQUIRED_ROLES_KEY = 'manar:required-roles';

/**
 * Coarse, endpoint-level role check enforced by `RolesGuard`
 * (`@RequireRole('SECURITY_ADMIN')`). Fine-grained, resource-scoped
 * authorization is OpenFGA's job (Phase 5) — not built here. A handler
 * with no `@RequireRole(...)` is only gated by `JwtAuthGuard` (any
 * authenticated user of the tenant may call it); listing multiple roles
 * means "any one of these roles is sufficient".
 */
export const RequireRole = (...roles: RoleName[]) =>
  SetMetadata(REQUIRED_ROLES_KEY, roles);
