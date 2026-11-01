import { Module } from '@nestjs/common';
import { HostMtlsModule } from '../host-mtls/host-mtls.module';
import {
  AiSpendController,
  HostAiUsageController,
} from './ai-spend.controller';
import { AiSpendService } from './ai-spend.service';

/** `POST /host/v1/ai-usage`; imported by the mTLS app only. */
@Module({
  imports: [HostMtlsModule],
  controllers: [HostAiUsageController],
  providers: [AiSpendService],
})
export class HostAiUsageModule {}

/** Console routes `/ai-spend`; imported by the human-facing app only. */
@Module({
  controllers: [AiSpendController],
  providers: [AiSpendService],
})
export class AiSpendHttpModule {}
