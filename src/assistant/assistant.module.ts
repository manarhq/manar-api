import { Module } from '@nestjs/common';
import { AiAdvisoryModule } from '../ai-advisory/ai-advisory.module';
import { LlmUpstreamClient } from '../agent-runtime/llm-upstream.client';
import { CatalogModule } from '../platform/catalog.module';
import { RedisThrottlerStorageModule } from '../rate-limit/redis-throttler-storage.module';
import { AssistantController } from './assistant.controller';
import { AssistantReader } from './assistant-reader.service';
import { AssistantService } from './assistant.service';

/**
 * The read-only console assistant (manar-api ADR-0008), on the human HTTP
 * app only. Nothing on the authorization decision path may import it
 * (`decision-path-dependencies.spec.ts`).
 */
@Module({
  imports: [AiAdvisoryModule, RedisThrottlerStorageModule, CatalogModule],
  controllers: [AssistantController],
  providers: [AssistantReader, AssistantService, LlmUpstreamClient],
})
export class AssistantModule {}
