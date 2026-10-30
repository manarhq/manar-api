import {
  CanActivate,
  createParamDecorator,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
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
@Injectable()
export class IdentityGuard implements CanActivate {
  constructor(private readonly tokenVerifier: TokenVerifierService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithIdentity>();
    const token = extractBearerToken(request.headers.authorization);
    if (!token) {
      throw new UnauthorizedException(
        'Missing or malformed Authorization header',
      );
    }
    request.identity = await this.tokenVerifier.verify(token);
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
