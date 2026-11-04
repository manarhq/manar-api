import {
  type CanActivate,
  type ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import type { StaffPermission } from '../rbac/permissions';
import { StaffRbacService } from '../rbac/staff-rbac.service';
import type { RequestWithStaff } from './staff-principal';
import { STEP_UP_KEY, checkStepUp } from './step-up';

export const STAFF_PERMISSION_KEY = 'staff:permission';
export const STAFF_SIGNED_IN_KEY = 'staff:signed-in';

/** The OpenFGA permission a staff route needs (spec §16 guard 2). */
export const RequirePermission = (p: StaffPermission) =>
  SetMetadata(STAFF_PERMISSION_KEY, p);
/** Any signed-in staff member (their own profile); routes must say so explicitly. */
export const StaffSignedIn = () => SetMetadata(STAFF_SIGNED_IN_KEY, true);

/**
 * Runs after StaffAuthGuard. Default deny: a staff route with neither @RequirePermission nor
 * @StaffSignedIn is refused, so a forgotten decorator cannot open a route. OpenFGA unreachable is
 * 503 `enforcement_dependency_unavailable`. Then the passkey re-check for @StepUp() routes, after
 * the permission, so someone without the permission is not asked for a passkey first.
 */
@Injectable()
export class StaffPermissionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly rbac: StaffRbacService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const targets = [ctx.getHandler(), ctx.getClass()];
    const staff = ctx.switchToHttp().getRequest<RequestWithStaff>().staff;
    if (!staff) throw new ForbiddenException();
    const permission = this.reflector.getAllAndOverride<
      StaffPermission | undefined
    >(STAFF_PERMISSION_KEY, targets);
    const signedInOnly = this.reflector.getAllAndOverride<boolean>(
      STAFF_SIGNED_IN_KEY,
      targets,
    );
    if (!permission && !signedInOnly)
      throw new ForbiddenException({ code: 'route_not_permitted' });
    if (permission) {
      let allowed: boolean;
      try {
        allowed = await this.rbac.can(staff.staffId, permission);
      } catch (error) {
        throwFailClosed('openfga', error);
      }
      if (!allowed)
        throw new ForbiddenException({
          code: 'permission_required',
          permission,
          message: "Your role doesn't allow this.",
        });
    }
    if (this.reflector.getAllAndOverride<boolean>(STEP_UP_KEY, targets))
      checkStepUp(staff);
    return true;
  }
}
