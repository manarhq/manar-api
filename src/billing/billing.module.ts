import { Global, Module } from '@nestjs/common';
import { EntitlementsService } from './entitlements.service';

/** Plans and limits, for every module that enforces them. Imported into AppModule. */
@Global()
@Module({
  providers: [EntitlementsService],
  exports: [EntitlementsService],
})
export class BillingModule {}
