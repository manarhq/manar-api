import { Module } from '@nestjs/common';
import { HostApprovalsModule } from '../approvals/host-approvals.module';
import { HostMtlsModule } from '../host-mtls/host-mtls.module';
import { LearningModule } from '../learning/learning.module';
import { KillSwitchesModule } from '../kill-switches/kill-switches.module';
import { PolicyModule } from '../policy/policy.module';
import { McpServersController } from '../mcp-inventory/mcp-servers.controller';
import { AiToolsController } from './ai-tools.controller';
import { HostAuthorizeService } from './host-authorize.service';
import { HostCoverageController } from './host-coverage.controller';
import { HostToolsService } from './host-tools.service';

/** Device routes `POST /host/v1/inventory` and `/authorize`; imported by the mTLS app only. */
@Module({
  imports: [
    HostMtlsModule,
    PolicyModule,
    KillSwitchesModule,
    HostApprovalsModule,
    LearningModule,
  ],
  controllers: [HostCoverageController],
  providers: [HostAuthorizeService],
})
export class HostCoverageModule {}

/** Console routes `/ai-tools`; imported by the human-facing app only. */
@Module({
  imports: [LearningModule],
  controllers: [AiToolsController, McpServersController],
  providers: [HostToolsService],
})
export class AiToolsHttpModule {}
