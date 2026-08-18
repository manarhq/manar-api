import { Module } from '@nestjs/common';
import { AgentMtlsGuard } from './agent-mtls.guard';

/**
 * `AgentMtlsGuard` as its own tiny exported module (Phase 5), rather than
 * a bare `providers` entry on `AgentMtlsAppModule` (Phase 4's original
 * wiring). `@UseGuards(AgentMtlsGuard)` resolves the guard class via the
 * DI graph of whichever module *declares the controller* using it, not
 * the whole application — so every module with an mTLS-gated controller
 * (`AgentWhoamiController` here, `AuthorizeController`/
 * `DelegationController` in Phase 5's new modules) needs `AgentMtlsGuard`
 * reachable in its own import graph. A shared, exported module is the
 * standard Nest way to give several sibling modules access to one guard
 * instance without each redeclaring it as its own provider (which would
 * construct a second instance per module, wasteful but also pointless
 * duplication of the same stateless guard).
 */
@Module({
  providers: [AgentMtlsGuard],
  exports: [AgentMtlsGuard],
})
export class AgentMtlsGuardModule {}
