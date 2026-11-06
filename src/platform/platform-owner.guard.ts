import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { RequestWithPlatformCaller } from './platform-auth.guard';

/**
 * Runs after `PlatformAuthGuard`: the platform token must also carry the staff Owner realm role
 * (`PLATFORM_OWNER_ROLE`). Used on routes that show money, which only Owners may see (decision 8).
 * Fails closed: no caller, no roles, or a different role is a 403.
 */
@Injectable()
export class PlatformOwnerGuard implements CanActivate {
  constructor(private readonly config: ConfigService<AppConfig, true>) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context
      .switchToHttp()
      .getRequest<RequestWithPlatformCaller>();
    const owner = this.config.get('PLATFORM_OWNER_ROLE', { infer: true });
    if (!request.platformCaller?.roles?.includes(owner))
      throw new ForbiddenException('Owners only');
    return true;
  }
}
