import { Global, Module } from '@nestjs/common';
import { KillSwitchService } from './kill-switch.service';
import { PlatformKillSwitchService } from './platform-kill-switch.service';
import { PlatformOperatorGuard } from './platform-operator.guard';

/**
 * Providers-only (no controller — see `KillSwitchHttpModule` for the
 * human-facing admin surface), mirroring `AuthorizationModule`/
 * `ApprovalsModule`'s split. `@Global()` for the same reason
 * `AuthorizationModule` is: `KillSwitchService.checkAll` is consumed by
 * `AuthorizationService` (both its first-attempt `authorize` and its
 * grant-redemption `authorizeRedemption`, which run in the mTLS app;
 * `GrantService` no longer calls it) — every app
 * graph that imports this module gets both services without needing a
 * second copy of "how to check the five kill-switch scopes."
 */
@Global()
@Module({
  providers: [
    PlatformKillSwitchService,
    KillSwitchService,
    PlatformOperatorGuard,
  ],
  exports: [
    PlatformKillSwitchService,
    KillSwitchService,
    PlatformOperatorGuard,
  ],
})
export class KillSwitchesModule {}
