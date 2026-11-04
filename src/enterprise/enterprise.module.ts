import { Module } from '@nestjs/common';
import { CatalogModule } from '../platform/catalog.module';
import { EnterpriseGateService } from './common/enterprise-gate.service';
import { DeviceSignatureGuard } from './watch/device-signature.guard';
import { WatchIdTokenVerifier } from './watch/id-token.verifier';
import { PolicyCompilerService } from './watch/policy-compiler.service';
import { WatchController } from './watch/watch.controller';
import { WatchDeviceService } from './watch/watch-device.service';

/**
 * Enterprise and Government "invisible mode" (docs/superpowers/specs/2026-11-04-enterprise-invisible-mode-design.md).
 * Inert unless a tenant's catalog flag `enterprise` is on and it has an enterprise profile.
 */
@Module({
  imports: [CatalogModule],
  controllers: [WatchController],
  providers: [
    EnterpriseGateService,
    DeviceSignatureGuard,
    WatchDeviceService,
    WatchIdTokenVerifier,
    PolicyCompilerService,
  ],
  exports: [EnterpriseGateService],
})
export class EnterpriseModule {}
