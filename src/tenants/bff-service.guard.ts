import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { FastifyRequest } from 'fastify';
import type { AppConfig } from '../config/env.validation';

/**
 * Gates `GET /tenants/:slug/oidc-client-secret` — the one piece of this
 * phase's OIDC-config surface that is genuinely sensitive (see
 * `tenants.controller.ts`'s doc comment for the full design). Mirrors
 * `PlatformOperatorGuard`'s exact shape (`src/kill-switches/platform-operator.guard.ts`):
 * a header-carried, non-tenant-scoped shared secret, checked with a
 * constant-shape comparison against `MANAR_BFF_SERVICE_TOKEN`
 * (`tenants.config.ts`).
 *
 * There is no `JwtAuthGuard` involved here at all, deliberately — unlike
 * `PlatformOperatorGuard` (which runs *in addition to* a real per-tenant
 * JWT), this endpoint is called by `manar-web`'s server-side BFF process
 * during the OIDC authorization-code exchange, before any Manar session
 * exists for the human at the other end. This guard's token is therefore
 * the *only* credential standing between an arbitrary caller and this
 * tenant's OIDC client secret — see `TenantsController`'s doc comment for
 * why that's still a materially narrower blast radius than the
 * Keycloak master-admin credentials this endpoint replaces.
 */
@Injectable()
export class BffServiceGuard implements CanActivate {
  constructor(private readonly configService: ConfigService<AppConfig, true>) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const provided = request.headers['x-manar-bff-token'];
    const expected = this.configService.get('MANAR_BFF_SERVICE_TOKEN', {
      infer: true,
    });

    if (
      typeof provided !== 'string' ||
      provided.length === 0 ||
      provided !== expected
    ) {
      throw new UnauthorizedException(
        'Missing or invalid BFF service credential',
      );
    }
    return true;
  }
}
