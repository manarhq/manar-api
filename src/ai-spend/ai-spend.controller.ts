import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiExcludeController,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { HostAuthGuard } from '../host-mtls/host-auth.guard';
import { CurrentHost, type HostContext } from '../host-mtls/host-context';
import {
  AiSpendService,
  AiSpendSettingsSchema,
  AiUsageBatchSchema,
} from './ai-spend.service';

const READ = ['AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const WRITE = ['SECURITY_ADMIN', 'TENANT_OWNER'] as const;

/** Device route (mTLS listener): DOOR's usage and secrets-guard report. */
@ApiExcludeController()
@Controller('host/v1')
@UseGuards(HostAuthGuard)
export class HostAiUsageController {
  constructor(private readonly spend: AiSpendService) {}

  @Post('ai-usage')
  @HttpCode(200)
  report(@CurrentHost() host: HostContext, @Body() body: unknown) {
    // A device the owner has not approved reports nothing: fail closed.
    if (host.status !== 'APPROVED')
      throw new ForbiddenException('device not approved');
    return this.spend.ingest(host, parseBodyOrThrow(AiUsageBatchSchema, body));
  }
}

/** Console routes (human listener): the AI spend page and its settings. */
@ApiTags('ai-spend')
@ApiBearerAuth('jwt')
@Controller('ai-spend')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AiSpendController {
  constructor(private readonly spend: AiSpendService) {}

  @Get()
  @RequireRole(...READ)
  @ApiOperation({
    summary:
      'AI spend per tool and model this week and month (list-price estimate)',
  })
  overview(@CurrentAuth() auth: AuthContext) {
    return this.spend.overview(auth.tenant.id);
  }

  @Put('settings')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary:
      'Set the monthly budget (alert), the monthly cap (pauses a tool) and the secrets guard mode',
  })
  settings(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    return this.spend.updateSettings(
      auth.tenant.id,
      parseBodyOrThrow(AiSpendSettingsSchema, body),
      { type: 'human', id: auth.user.id },
    );
  }
}
