import { Controller, Get, Logger, UseGuards } from '@nestjs/common';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { SecretsService } from '../secrets/secrets.service';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { ApiExcludeController } from '@nestjs/swagger';
import { CurrentHost, type HostContext } from './host-context';
import { HostAuthGuard } from './host-auth.guard';

export type StartMode = 'watch' | 'ask' | 'strict';

/** The mode a workspace has until its owner picks one (spec 4.7: "Ask me for risky things"). */
export const DEFAULT_START_MODE: StartMode = 'ask';

@ApiTags('host')
@ApiExcludeController()
@Controller('host/v1')
@UseGuards(HostAuthGuard)
export class HostConfigController {
  private readonly log = new Logger(HostConfigController.name);

  constructor(
    private readonly tools: HostToolsService,
    private readonly tenants: TenantDatabaseManager,
    private readonly secrets: SecretsService,
  ) {}

  /** Secret blocking flags. Any failure reads as "off": a lookup problem must never lock a person out. */
  private async secretFeatures(host: HostContext): Promise<string[]> {
    if (host.status !== 'APPROVED') return [];
    try {
      return await this.secrets.features(
        await this.tenants.getClient(host.tenantId),
      );
    } catch (e) {
      this.log.warn(`secret features unavailable: ${(e as Error).message}`);
      return [];
    }
  }

  @Get('config')
  @ApiOperation({
    summary: 'The effective preset and feature flags for this device',
  })
  async config(@CurrentHost() host: HostContext) {
    return {
      hostId: host.hostId,
      status: host.status,
      // The `features` track stores the workspace's mode (PUT /workspace/start-mode) and
      // replaces this default with a read of it.
      startMode: DEFAULT_START_MODE,
      features: await this.secretFeatures(host),
      // Tools whose owner turned protection off; the device restores their backups.
      tools: await this.tools.instructions(host),
    };
  }
}
