import { Global, Module } from '@nestjs/common';
import { RestrictionEnforcement } from './restriction-enforcement';

/**
 * The restriction lookup, global in every app that authenticates customers or their devices, so
 * every guard that needs it (HostAuthGuard in any host module, the token verifier) resolves it.
 */
@Global()
@Module({
  providers: [RestrictionEnforcement],
  exports: [RestrictionEnforcement],
})
export class RestrictionEnforcementModule {}
