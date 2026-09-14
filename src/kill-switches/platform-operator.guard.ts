import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { FastifyRequest } from 'fastify';
import type { AppConfig } from '../config/env.validation';
import { constantTimeEqual } from '../common/security/constant-time-compare';

/**
 * Gates `POST /kill-switches/platform`(`/deactivate`) — see
 * `docs/kill-switches.md` for the full "no application-level super admin"
 * reasoning this resolves (Section 11's explicit tension the design spec
 * flags for this exact endpoint).
 *
 * A per-tenant role, however privileged (`SECURITY_ADMIN`/`TENANT_OWNER`),
 * is scoped by construction to whichever tenant's Keycloak realm issued the
 * caller's token (`JwtAuthGuard` resolves `AuthContext.tenant` from the
 * token's issuer) — Section 11 never defined, and this codebase never
 * built, any role that spans tenants. Gating the single most
 * destructive/cross-tenant lever in the product behind *only* a per-tenant
 * role would mean any one tenant's admin could deny every other tenant —
 * a de facto application-level super admin materializing by accident. This
 * guard closes that gap by requiring possession of a second, genuinely
 * separate credential that is never distributed through any tenant's
 * Keycloak realm/RBAC at all (`PLATFORM_KILL_SWITCH_OPERATOR_TOKEN`) — the
 * same "operator-only, outside the application's own RBAC" trust boundary
 * `CONTROL_DATABASE_URL`/`TENANT_DB_BASE_URL` already sit behind.
 *
 * Runs in *addition to* `JwtAuthGuard`+`RolesGuard`
 * (`KillSwitchesController` still requires both) — never instead of them:
 * the caller must still be an authenticated human holding
 * `SECURITY_ADMIN`/`TENANT_OWNER` in their own tenant, so there remains a
 * real, attributable `UserProfile` actor for the audit trail this
 * endpoint's own tenant-DB `AuditEvent` records. The token itself is
 * compared against `PLATFORM_KILL_SWITCH_OPERATOR_TOKEN` in constant time
 * (`constantTimeEqual`) rather than with a plain `!==`, which would leak
 * the expected value one byte at a time to anyone able to time enough
 * requests against the most destructive lever in the product.
 *
 * This mirrors the codebase's existing precedent for genuinely cross-tenant operations having no
 * per-tenant-RBAC-only path at all (`pnpm manar tenant:create` is CLI-only,
 * operator-host-access-gated, not a `RolesGuard`-gated HTTP endpoint — see
 * docs/tenant-isolation.md) while still meeting the design spec's explicit
 * ask for `POST /kill-switches/platform` to exist as a real, JWT-guarded
 * HTTP endpoint (unlike tenant creation, which the spec never asks for over
 * HTTP at all).
 */
@Injectable()
export class PlatformOperatorGuard implements CanActivate {
  constructor(private readonly configService: ConfigService<AppConfig, true>) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const provided = request.headers['x-platform-operator-token'];
    const expected = this.configService.get(
      'PLATFORM_KILL_SWITCH_OPERATOR_TOKEN',
      { infer: true },
    );

    if (
      typeof provided !== 'string' ||
      provided.length === 0 ||
      !constantTimeEqual(provided, expected)
    ) {
      throw new UnauthorizedException(
        'Missing or invalid platform operator credential',
      );
    }
    return true;
  }
}
