import { Module } from '@nestjs/common';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { ToolsModule } from '../tools/tools.module';
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
 *
 * Phase 15a: imports `ToolsModule` for `ToolRegistryService` — `PolicyEngine`
 * needs it to resolve a request's `ToolAction.classification` for
 * `resourceClassification` rule matching (Section 53). Mirrors
 * `RiskModule`'s identical import of `ToolsModule` for the same service.
 *
 * Phase 10c: imports `AiAdvisoryModule` — `PolicyService.suggestPolicy`
 * needs `AiAdvisoryClient` for `POST /policies/suggest`.
 */
@Module({
  imports: [ToolsModule, AiAdvisoryModule],
  providers: [PolicyEngine, PolicyService],
  exports: [PolicyEngine, PolicyService],
})
export class PolicyModule {}
