import { Module } from '@nestjs/common';
import { AgentEnrollController } from './agent-enroll.controller';
import { AgentsController } from './agents.controller';
import { AgentsService } from './agents.service';
import { CertificateAuthorityService } from './certificate-authority.service';

/**
 * The human-facing (`AgentsController`, JWT+role-gated) and agent-facing
 * (`AgentEnrollController`, token-gated) halves of Section 14's enrollment
 * flow. `DatabaseModule`/`AuthModule`/`OpenBaoModule` are `@Global()`
 * (see their own doc comments) so nothing needs importing here beyond
 * this module's own providers/controllers.
 *
 * `CertificateAuthorityService` is exported so `AgentMtlsModule` (the
 * separate `/agent/v1/*` mTLS application — see src/agent-mtls/) can reuse
 * it without a second instance; `AgentsService` likewise, for anything
 * Phase 5+ needs from that surface.
 */
@Module({
  controllers: [AgentsController, AgentEnrollController],
  providers: [AgentsService, CertificateAuthorityService],
  exports: [AgentsService, CertificateAuthorityService],
})
export class AgentsModule {}
