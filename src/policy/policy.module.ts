import { Module } from '@nestjs/common';
import { PolicyEngine } from './policy-engine.service';
import { PolicyService } from './policy.service';

/**
 * Providers-only (no controller) — same split `TasksModule`/`AgentsModule`
 * establish. `PolicyEngine` is needed by both Nest applications: the
 * agent-facing mTLS app (`AuthorizationService`'s pipeline, via
 * `AgentAuthorizeModule`) and, indirectly, nowhere else this phase (there
 * is no human-facing "preview a policy decision" endpoint). `PolicyService`
 * (the `/policies` CRUD) is only ever consumed by the human-facing
 * `PolicyHttpModule`. Both are exported from here regardless, so either
 * app can import exactly what it needs without a controller ever being
 * reachable from the wrong listener.
 */
@Module({
  providers: [PolicyEngine, PolicyService],
  exports: [PolicyEngine, PolicyService],
})
export class PolicyModule {}
