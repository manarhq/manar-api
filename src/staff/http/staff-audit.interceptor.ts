import {
  type CallHandler,
  type ExecutionContext,
  Injectable,
  type NestInterceptor,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { mergeMap, type Observable } from 'rxjs';
import { throwFailClosed } from '../../common/fail-closed/fail-closed';
import { StaffAuditService } from '../audit/staff-audit.service';
import type { RequestWithStaff } from '../auth/staff-principal';

export const NO_STAFF_AUDIT_KEY = 'staff:no-audit';
/** Only for a caller reading their own profile; every other staff route is recorded. */
export const NoStaffAudit = () => SetMetadata(NO_STAFF_AUDIT_KEY, true);

/**
 * Spec §16: every staff route writes the staff audit chain. Appended after the handler succeeds
 * and before the response leaves, so a read of customer data that cannot be recorded is not
 * returned (503). Records the route template, the ids in the path and the search text, never a
 * request body (services record the meaningful fields of their own actions).
 */
@Injectable()
export class StaffAuditInterceptor implements NestInterceptor {
  constructor(
    private readonly reflector: Reflector,
    private readonly audit: StaffAuditService,
  ) {}

  intercept(ctx: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = ctx.switchToHttp().getRequest<RequestWithStaff>();
    const skip = this.reflector.getAllAndOverride<boolean>(NO_STAFF_AUDIT_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    return next.handle().pipe(
      mergeMap(async (body: unknown) => {
        if (skip || !request.staff) return body;
        const params = (request.params ?? {}) as Record<string, string>;
        const query = (request.query ?? {}) as Record<string, unknown>;
        try {
          await this.audit.append({
            staffId: request.staff.staffId,
            action: `http ${request.method} ${request.routeOptions?.url ?? ''}`,
            targetId:
              params.accountId ??
              params.tenantId ??
              params.id ??
              params.reference,
            data: {
              params,
              peerIp: request.staff.peerIp ?? null,
              ...(typeof query.q === 'string'
                ? { q: query.q.slice(0, 200) }
                : {}),
            },
            ip: request.staff.ip,
            requestId: request.staff.requestId,
          });
        } catch (error) {
          throwFailClosed('staff-audit', error);
        }
        return body;
      }),
    );
  }
}
