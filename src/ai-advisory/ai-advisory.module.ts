import { Module } from '@nestjs/common';
import { AiAdvisoryClient } from './ai-advisory-client.service';

/**
 * Providers-only module (no controller — `AiAdvisoryClient` is only ever
 * consumed by other services, never directly reachable via any HTTP route
 * of its own), mirroring `RiskModule`/`ToolsModule`'s shape. Imported by
 * `RiskModule` (activates `aiAdvisoryScore`) and `ToolsModule`
 * (`CredentialBrokerService`'s DLP/prompt-injection checkpoints) — see
 * docs/ai-security-model.md.
 */
@Module({
  providers: [AiAdvisoryClient],
  exports: [AiAdvisoryClient],
})
export class AiAdvisoryModule {}
