import { Module } from '@nestjs/common';
import { AgentEnrollController } from './agent-enroll.controller';
import { AgentsController } from './agents.controller';
import { AgentsModule } from './agents.module';

/**
 * The human-facing (`AgentsController`, JWT+role-gated) and agent-facing
 * (`AgentEnrollController`, token-gated) HTTP surface for Section 14's
 * enrollment flow. Split out from `AgentsModule` (Phase 5) so the
 * *services* (`AgentsService`/`CertificateAuthorityService`) can be
 * reused by `AgentMtlsAppModule` without also exposing these
 * `JwtAuthGuard`-gated routes on the mTLS-only listener — see
 * `AgentsModule`'s doc comment. Imported only into `AppModule`.
 */
@Module({
  imports: [AgentsModule],
  controllers: [AgentsController, AgentEnrollController],
})
export class AgentsHttpModule {}
