import { Module } from '@nestjs/common';
import { AgentsService } from './agents.service';
import { CertificateAuthorityService } from './certificate-authority.service';

/**
 * Providers-only (`AgentsService` + `CertificateAuthorityService`), no
 * controllers — split out from the HTTP surface (`AgentsHttpModule`,
 * `AgentsController` + `AgentEnrollController`) specifically so Phase 5's
 * `AgentMtlsAppModule` can import *this* module to reuse both services for
 * delegation's child-agent creation "without a second instance" (this
 * module's doc comment promised exactly that back in Phase 4, before the
 * split existed to actually make it safe) without also dragging
 * `AgentsController`'s `JwtAuthGuard`-gated routes onto the mTLS-only
 * listener — that listener's `https` options require a client
 * certificate for *every* request (`rejectUnauthorized: true`, see
 * src/main.ts), so a JWT-gated route imported there would be
 * structurally unreachable by any human caller in the first place, quite
 * apart from the DI problem (`JwtAuthGuard`'s own dependencies live in
 * `AuthModule`, which `AgentMtlsAppModule` deliberately never imports).
 *
 * `DatabaseModule`/`OpenBaoModule` are `@Global()` (see their own doc
 * comments) so nothing needs importing here beyond this module's own
 * providers.
 */
@Module({
  providers: [AgentsService, CertificateAuthorityService],
  exports: [AgentsService, CertificateAuthorityService],
})
export class AgentsModule {}
