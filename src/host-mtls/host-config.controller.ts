import { Controller, Get, Logger, UseGuards } from '@nestjs/common';
import { AiSpendService } from '../ai-spend/ai-spend.service';
import { HostToolsService } from '../host-coverage/host-tools.service';
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
  private readonly logger = new Logger(HostConfigController.name);

  constructor(
    private readonly tools: HostToolsService,
    private readonly spend: AiSpendService,
  ) {}

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
      features: [] as string[],
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
    };
  }
}
