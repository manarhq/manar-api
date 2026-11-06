import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { PlatformAuthGuard } from '../platform/platform-auth.guard';
import { parseDays } from './friction.controller';
import { FrictionService } from './friction.service';

/**
 * Staff view for Desk. Who may open it (Owner role) is decided by Desk; this API only knows the
 * platform client. The same numbers as the customer page, per workspace, flagged above 5 prompts
 * per developer per day.
 */
@ApiTags('platform')
@ApiBearerAuth('platform')
@UseGuards(PlatformAuthGuard)
@Controller('platform/v1/friction')
export class FrictionPlatformController {
  constructor(private readonly friction: FrictionService) {}

  @Get()
  @ApiOperation({ summary: 'Friction per workspace, over-budget first' })
  @ApiQuery({
    name: 'days',
    required: false,
    description: '1 to 90, default 7',
  })
  async list(@Query('days') days?: string) {
    const { workspaces, failed } = await this.friction.staffReport(
      parseDays(days, 7),
    );
    // Keeps the gauge and the warn log current whenever Desk looks.
    void this.friction.scan().catch(() => undefined);
    return {
      budget: 5,
      overBudget: workspaces.filter((w) => w.overBudget).length,
      workspaces,
      // Workspaces that could not be read this time (also in the log); empty when all were.
      failed,
    };
  }
}
