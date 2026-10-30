import {
  CallHandler,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import type { Observable } from 'rxjs';
import type { RequestWithAuthContext } from '../auth/auth-context';
import { EntitlementsService } from './entitlements.service';

/** Still allowed in a read-only workspace: pay, export, verify. */
const STILL_ALLOWED = ['/billing', '/evidence', '/audit/investigate'];

/**
 * A workspace whose company trial ended unpaid is read-only plus export: every write on the
 * console API is refused. Runs after the guards, so `authContext` is set on authenticated routes;
 * platform and public routes carry none and pass through.
 */
@Injectable()
export class ReadOnlyInterceptor implements NestInterceptor {
  constructor(private readonly entitlements: EntitlementsService) {}

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<unknown>> {
    if (context.getType() !== 'http') return next.handle();
    const req = context.switchToHttp().getRequest<RequestWithAuthContext>();
    const tenantId = req.authContext?.tenant.id;
    if (!tenantId || ['GET', 'HEAD', 'OPTIONS'].includes(req.method))
      return next.handle();
    const path = req.url.split('?')[0]!;
    if (STILL_ALLOWED.some((p) => path === p || path.startsWith(`${p}/`)))
      return next.handle();
    const e = await this.entitlements.get(tenantId);
    if (e.status === 'read_only')
      throw new ForbiddenException({
        statusCode: 403,
        code: 'workspace_read_only',
        message:
          'This workspace is read-only. Upgrade to make changes; export stays available.',
        upgradeUrl: this.entitlements.upgradeUrl(),
      });
    return next.handle();
  }
}
