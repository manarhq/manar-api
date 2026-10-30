import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { FastifyRequest } from 'fastify';
import type { RoleName } from './roles';
import type { WorkspaceKind } from './membership.service';

/**
 * The trustworthy identity context `JwtAuthGuard` attaches to a request on
 * successful token verification. This is the only source of tenant/user
 * identity every downstream module (agents, tasks, authorization, ...)
 * should key off — never a client-supplied tenant ID from a header, query
 * param, or request body (Section 23 of the master prompt).
 */
export interface AuthContext {
  /** Issuer of the token the caller signed in with (a `sub` is only unique within an issuer). */
  issuer: string;
  tenant: {
    id: string;
    slug: string;
  };
  user: {
    id: string;
    keycloakSubject: string;
    email: string;
    displayName: string;
  };
  /** From the Membership row, never from the token. */
  roles: RoleName[];
  workspaceKind: WorkspaceKind;
}

/** The property `JwtAuthGuard` attaches `AuthContext` to on the request. */
export type RequestWithAuthContext = FastifyRequest & {
  authContext?: AuthContext;
};

/**
 * Controller-facing accessor for the `AuthContext` `JwtAuthGuard` attaches
 * to the request. Throws if used on a route that isn't guarded by
 * `JwtAuthGuard` (a request with no `authContext` means the guard never
 * ran, which is a wiring bug, not a valid "unauthenticated" state — an
 * unauthenticated request is rejected by the guard itself before reaching
 * the handler).
 */
export const CurrentAuth = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AuthContext => {
    const request = context.switchToHttp().getRequest<RequestWithAuthContext>();
    if (!request.authContext) {
      throw new Error(
        '@CurrentAuth() used on a route with no AuthContext attached — is JwtAuthGuard applied to this route?',
      );
    }
    return request.authContext;
  },
);
