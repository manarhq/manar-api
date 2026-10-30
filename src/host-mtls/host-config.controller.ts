import { Controller, Get, UseGuards } from '@nestjs/common';
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
  @Get('config')
  @ApiOperation({
    summary: 'The effective preset and feature flags for this device',
  })
  config(@CurrentHost() host: HostContext) {
    return {
      hostId: host.hostId,
      status: host.status,
      // The `features` track stores the workspace's mode (PUT /workspace/start-mode) and
      // replaces this default with a read of it.
      startMode: DEFAULT_START_MODE,
      features: [] as string[],
    };
  }
}
