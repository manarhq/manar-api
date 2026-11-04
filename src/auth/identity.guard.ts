import {
  CanActivate,
  createParamDecorator,
  ExecutionContext,
  Injectable,
  Optional,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { FastifyRequest } from 'fastify';
import {
  extractBearerToken,
  TokenVerifierService,
  type VerifiedIdentity,
} from './token-verifier.service';

export type RequestWithIdentity = FastifyRequest & {
  identity?: VerifiedIdentity;
};

/**
 * Token-only guard for the routes that must work before the caller has a workspace
 * (`/workspaces/*`: first sign-in, company discovery, request to join). It attaches a verified
 * identity and nothing else: no tenant, no roles, no tenant database access.
 */
export const ALLOW_RESTRICTED_KEY = 'auth:allow-restricted';
/**
 * A suspended or banned person may still call this route (their restriction, appeal, data
 * export; DESK spec §9.2). Only on IdentityGuard routes; JwtAuthGuard never admits them.
 */
export const AllowRestricted = () => SetMetadata(ALLOW_RESTRICTED_KEY, true);

@Injectable()
export class IdentityGuard implements CanActivate {
  constructor(
    private readonly tokenVerifier: TokenVerifierService,
    @Optional() private readonly reflector?: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithIdentity>();
    const token = extractBearerToken(request.headers.authorization);
    if (!token) {
      throw new UnauthorizedException(
        'Missing or malformed Authorization header',
      );
    }
    const allowRestricted = !!this.reflector?.getAllAndOverride<boolean>(
      ALLOW_RESTRICTED_KEY,
      [context.getHandler(), context.getClass()],
    );
    request.identity = await this.tokenVerifier.verify(token, {
      allowRestricted,
    });
    return true;
  }
}

export const CurrentIdentity = createParamDecorator(
  (_d: unknown, context: ExecutionContext): VerifiedIdentity => {
    const request = context.switchToHttp().getRequest<RequestWithIdentity>();
    if (!request.identity) {
      throw new Error(
        '@CurrentIdentity() used on a route without IdentityGuard',
      );
    }
    return request.identity;
  },
);
