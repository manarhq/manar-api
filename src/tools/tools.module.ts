import { Module } from '@nestjs/common';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { CredentialBrokerService } from './credential-broker.service';
import { HttpToolAdapter } from './http-tool.adapter';
import { McpToolAdapter } from './mcp-tool.adapter';
import { ToolRegistryService } from './tool-registry.service';

/**
 * Providers-only module (no controller — see `ToolInvokeModule` for the
 * agent-facing HTTP surface), mirroring `AuthorizationModule`/`PolicyModule`'s
 * split: `ToolRegistryService` is consumed by both `CredentialBrokerService`
 * (this module) and `RiskEngine` (`RiskModule`, which imports this module
 * directly), so it lives in its own shared module rather than being
 * private to either consumer. Since Phase 10b, `AiAdvisoryModule` is
 * imported here too — `CredentialBrokerService`'s before/after-call DLP
 * checkpoints and prompt-injection advisory (see docs/ai-security-model.md)
 * need `AiAdvisoryClient`.
 */
@Module({
  imports: [AiAdvisoryModule],
  providers: [
    ToolRegistryService,
    HttpToolAdapter,
    McpToolAdapter,
    CredentialBrokerService,
  ],
  exports: [ToolRegistryService, CredentialBrokerService],
})
export class ToolsModule {}
