import { Global, Module } from '@nestjs/common';
import { PlatformAuthGuard } from '../platform/platform-auth.guard';
import { PlatformOwnerGuard } from '../platform/platform-owner.guard';
import { AiTelemetryService } from './ai-telemetry.service';
import { PlatformAiUsageController } from './platform-ai-usage.controller';

/** The recorder: imported by every module that makes model calls (HTTP app and worker). */
@Global()
@Module({
  providers: [AiTelemetryService],
  exports: [AiTelemetryService],
})
export class AiTelemetryModule {}

/** Staff routes `/platform/v1/ai-usage`; human HTTP app only. */
@Module({
  imports: [AiTelemetryModule],
  controllers: [PlatformAiUsageController],
  providers: [PlatformAuthGuard, PlatformOwnerGuard],
})
export class PlatformAiUsageModule {}
