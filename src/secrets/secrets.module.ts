import { forwardRef, Module } from '@nestjs/common';
import { HostMtlsModule } from '../host-mtls/host-mtls.module';
import { ApproverDirectory } from '../approvals/approver-directory';
import { SecretAlertBus } from './secret-alert-bus';
import { SecretsHostController } from './secrets-host.controller';
import { SecretsController } from './secrets.controller';
import { SecretsService } from './secrets.service';

/** Services shared by both listeners. `SecretAlertBus` is what the approvals track subscribes to. */
@Module({
  providers: [SecretsService, SecretAlertBus],
  exports: [SecretsService, SecretAlertBus],
})
export class SecretsModule {}

/** Console routes (`/secrets/*`, JWT) on the human listener. */
@Module({
  imports: [SecretsModule],
  controllers: [SecretsController],
  // Who may decide a vault request: the same approval rights as device approvals.
  providers: [ApproverDirectory],
})
export class SecretsHttpModule {}

/**
 * Device routes (`/host/v1/events`, `/host/v1/secrets/*`) on the mTLS listener. `forwardRef`:
 * host-mtls.module.ts imports this file for `SecretsModule`, so `HostMtlsModule` can still be
 * undefined while this decorator runs.
 */
@Module({
  imports: [SecretsModule, forwardRef(() => HostMtlsModule)],
  controllers: [SecretsHostController],
})
export class SecretsHostModule {}
