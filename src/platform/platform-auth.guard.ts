import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { FastifyRequest } from 'fastify';
import { errors as joseErrors, jwtVerify } from 'jose';
import type { AppConfig } from '../config/env.validation';
import { ACCEPTED_SIGNING_ALGORITHMS } from '../auth/jwt-auth.guard';
import { JwksCacheService } from '../auth/jwks-cache.service';

export interface PlatformCaller {
  clientId: string;
  subject: string;
}

export type RequestWithPlatformCaller = FastifyRequest & {
  platformCaller?: PlatformCaller;
};

/**
 * Guards /platform/v1/* (ADR-0010). Accepts only access tokens from PLATFORM_API_ISSUER, verified
 * against that realm's JWKS, issued to PLATFORM_API_CLIENT_ID (azp), carrying the realm role
 * PLATFORM_API_ROLE. Fails closed: the API is off when the issuer is unset, and an unreachable
 * JWKS denies with 503. Tenant realm tokens never pass: their issuer differs.
 */
@Injectable()
export class PlatformAuthGuard implements CanActivate {
  private readonly logger = new Logger(PlatformAuthGuard.name);

  constructor(
    private readonly config: ConfigService<AppConfig, true>,
    private readonly jwksCache: JwksCacheService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const issuer = this.config.get('PLATFORM_API_ISSUER', { infer: true });
    if (!issuer) {
      throw new ServiceUnavailableException(
        'The platform API is not enabled on this deployment',
      );
    }
    const request = context
      .switchToHttp()
      .getRequest<RequestWithPlatformCaller>();
    const match = /^Bearer\s+(\S+)$/.exec(request.headers.authorization ?? '');
    if (!match?.[1]) throw new UnauthorizedException('Bearer token required');

    const clientId = this.config.get('PLATFORM_API_CLIENT_ID', { infer: true });
    const role = this.config.get('PLATFORM_API_ROLE', { infer: true });
    let payload: Record<string, unknown>;
    try {
      ({ payload } = await jwtVerify(match[1], this.jwksCache.getJwks(issuer), {
        issuer,
        algorithms: [...ACCEPTED_SIGNING_ALGORITHMS],
        requiredClaims: ['exp', 'sub'],
      }));
    } catch (error) {
      const unavailable =
        !(error instanceof joseErrors.JOSEError) ||
        error instanceof joseErrors.JWKSTimeout ||
        error.code === 'ERR_JOSE_GENERIC';
      if (unavailable) {
        this.logger.warn('Platform JWKS unavailable; denying');
        throw new ServiceUnavailableException(
          'enforcement_dependency_unavailable',
        );
      }
      this.logger.warn(`Rejected platform token: ${error.code}`);
      throw new UnauthorizedException('Invalid platform token');
    }

    if (payload.typ !== 'Bearer' || payload.azp !== clientId) {
      this.logger.warn('Rejected platform token: wrong type or client');
      throw new UnauthorizedException('Invalid platform token');
    }
    const roles = (payload.realm_access as { roles?: unknown } | undefined)
      ?.roles;
    if (!Array.isArray(roles) || !roles.includes(role)) {
      throw new ForbiddenException('Missing the platform role');
    }
    request.platformCaller = { clientId, subject: String(payload.sub) };
    return true;
  }
}
