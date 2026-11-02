import { Controller, Get, Logger, UseGuards } from '@nestjs/common';
import { AiSpendService } from '../ai-spend/ai-spend.service';
import { HostToolsService } from '../host-coverage/host-tools.service';
import { ApiExcludeController, ApiOperation, ApiTags } from '@nestjs/swagger';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { PauseService } from '../pause/pause.service';
import { SecretsService } from '../secrets/secrets.service';
import { DataCollectionService } from '../data-collection/data-collection.service';
import { JailSitesService } from '../jail/jail-sites.service';
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
  private readonly logger = new Logger(HostConfigController.name);

  constructor(
    private readonly tools: HostToolsService,
    private readonly pause: PauseService,
    private readonly spend: AiSpendService,
    private readonly tenants: TenantDatabaseManager,
    private readonly secrets: SecretsService,
    private readonly jail: JailSitesService,
    private readonly data: DataCollectionService,
  ) {}

  /** Secret blocking flags. Any failure reads as "off": a lookup problem must never lock a person out. */
  private async secretFeatures(host: HostContext): Promise<string[]> {
    if (host.status !== 'APPROVED') return [];
    try {
      return await this.secrets.features(
        await this.tenants.getClient(host.tenantId),
      );
    } catch (e) {
      this.logger.warn(`secret features unavailable: ${(e as Error).message}`);
      return [];
    }
  }

  private async dataCollection(host: HostContext) {
    try {
      return (await this.data.forHost(host.tenantId, host.ownerSubject))
        .effective;
    } catch (e) {
      this.logger.warn(
        `data collection flags unavailable: ${(e as Error).message}`,
      );
      return { improveManar: false, aiTraining: false };
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
      // Secret blocking flags, plus `undo`: snapshot files an AI tool edits outside its project,
      // restore on request.
      features: [
        ...(await this.secretFeatures(host)),
        ...(process.env.HOST_UNDO_ENABLED === 'false' ? [] : ['undo']),
      ],
      // "Pause all AI": while true the device denies every protected tool with reason `paused`.
      paused: await this.pause.isPaused(host.tenantId),
      // Tools whose owner turned protection off; the device restores their backups.
      tools: await this.tools.instructions(host),
      // DOOR: secrets guard mode and tools paused by the monthly spend cap.
      door: await this.spend.doorConfig(host).catch((e: unknown) => {
        // Not worth failing the whole config for: the device keeps its last DOOR settings.
        this.logger.error(
          `door config: ${e instanceof Error ? e.message : String(e)}`,
        );
        return { unavailable: true };
      }),
      // JAIL: which tools the device filters and the remembered site decisions (owned by the jail track).
      jail: await this.jail.config(host),
      // Product improvement data: the device owner's effective switches. Off on any failure.
      dataCollection: await this.dataCollection(host),
    };
  }
}
