import { Module } from '@nestjs/common';
import { PlatformAuthGuard } from '../platform/platform-auth.guard';
import {
  PlatformLicenseController,
  TenantLicenseController,
} from './license.controller';
import { LicenseService } from './license.service';

/**
 * Signed offline licence, soft limits (docs/licensing.md). Imported only into AppModule (the
 * human HTTP app). `ControlPrismaService`/`TenantDatabaseManager` and `AuthModule` are global.
 */
@Module({
  controllers: [PlatformLicenseController, TenantLicenseController],
  providers: [LicenseService, PlatformAuthGuard],
})
export class LicensingModule {}
