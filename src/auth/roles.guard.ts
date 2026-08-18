import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RequestWithAuthContext } from './auth-context';
import { REQUIRED_ROLES_KEY } from './require-role.decorator';
import type { RoleName } from './roles';

/**
 * Coarse role-based endpoint protection. Must run after `JwtAuthGuard`
 * (Nest evaluates a route's guards in array order — see how both are
 * applied together via `@UseGuards(JwtAuthGuard, RolesGuard)`), since it
 * reads the `AuthContext` that guard attaches.
 *
 * A route with no `@RequireRole(...)` metadata is allowed through
 * (`JwtAuthGuard` alone already required authentication) — `RolesGuard`
 * only adds a check when the handler or controller explicitly declares
 * one.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<
      RoleName[] | undefined
    >(REQUIRED_ROLES_KEY, [context.getHandler(), context.getClass()]);

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<RequestWithAuthContext>();
    const authContext = request.authContext;
    if (!authContext) {
      throw new UnauthorizedException(
        'RolesGuard requires JwtAuthGuard to run first',
      );
    }

    const hasRequiredRole = requiredRoles.some((role) =>
      authContext.roles.includes(role),
    );
    if (!hasRequiredRole) {
      throw new ForbiddenException(
        `Requires one of the following role(s): ${requiredRoles.join(', ')}`,
      );
    }

    return true;
  }
}
