import { Module } from '@nestjs/common';
import { PlatformAuthGuard } from './platform-auth.guard';
import { PlatformController } from './platform.controller';
import { PlatformService } from './platform.service';

/** Imported only into AppModule (the human HTTP app), never the agent mTLS listener. */
@Module({
  controllers: [PlatformController],
  providers: [PlatformService, PlatformAuthGuard],
})
export class PlatformModule {}
