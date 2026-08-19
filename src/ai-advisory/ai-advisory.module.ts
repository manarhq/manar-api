import { Module } from '@nestjs/common';
import { DatabaseModule } from '../database/database.module';
import { AiAdvisoryClient } from './ai-advisory-client.service';

/**
 * Providers-only module (no controller — `AiAdvisoryClient` is only ever
 * consumed by other services, never directly reachable via any HTTP route
 * of its own), mirroring `RiskModule`/`ToolsModule`'s shape. Imported by
 * `RiskModule` (activates `aiAdvisoryScore`) and `ToolsModule`
 * (`CredentialBrokerService`'s DLP/prompt-injection checkpoints) — see
 * docs/ai-security-model.md. Imports `DatabaseModule` explicitly (even
 * though it's `@Global()`) so `AiAdvisoryClient`'s dependency on
 * `ControlPrismaService` (Phase 12a's data-residency `allowExternalAi`
 * check) is visible from this file alone — the same "explicit even when
 * global" convention `DatabaseModule`'s own doc comment establishes for
 * `OpenBaoModule`.
 */
@Module({
  imports: [DatabaseModule],
  providers: [AiAdvisoryClient],
  exports: [AiAdvisoryClient],
})
export class AiAdvisoryModule {}
