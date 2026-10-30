import { ForbiddenException } from '@nestjs/common';
import type { LimitName } from './plans';

/**
 * Thrown by `EntitlementsService.assertWithin`. It is a 403, so any route that lets it escape
 * answers `{ code: 'plan_limit_reached', limit, current, max, upgradeUrl }`.
 */
export class PlanLimitError extends ForbiddenException {
  constructor(
    readonly limit: LimitName,
    readonly current: number,
    readonly max: number,
    readonly upgradeUrl: string,
  ) {
    super({
      statusCode: 403,
      code: 'plan_limit_reached',
      limit,
      current,
      max,
      upgradeUrl,
    });
  }
}
