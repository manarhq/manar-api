import { Module } from '@nestjs/common';
import { FrictionController } from './friction.controller';
import { FrictionService } from './friction.service';

/** Friction metrics (decision 38). The console route is on the human HTTP app only. */
@Module({
  controllers: [FrictionController],
  providers: [FrictionService],
  exports: [FrictionService],
})
export class FrictionModule {}
