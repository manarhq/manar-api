import { Body, Controller, Get, Put, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { StartModeService } from './start-mode.service';
import { SetStartModeRequestDto, StartModeResponseDto } from './workspace.dto';
import { SetStartModeSchema } from './workspace.validation';

/** The caller's own workspace only; the tenant comes from the token, never from the URL. */
@ApiTags('workspace')
@ApiBearerAuth('jwt')
@Controller('workspace/start-mode')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
export class StartModeController {
  constructor(
    private readonly startMode: StartModeService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'Get the start mode',
    description:
      'watch, ask or strict; custom when the rules were edited by hand. A workspace that never chose one is set to ask.',
  })
  @ApiResponse({ status: 200, type: StartModeResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async get(@CurrentAuth() auth: AuthContext): Promise<StartModeResponseDto> {
    const client = await this.tenantDatabaseManager.getClient(auth.tenant.id);
    const s = await this.startMode.currentOrSeed(
      client,
      auth.tenant.id,
      auth.user.id,
    );
    return { mode: s.mode };
  }

  @Put()
  @ApiOperation({
    summary: 'Switch the start mode',
    description:
      'Swaps the active policy set in one transaction and records start_mode.changed. Takes effect on the next decision.',
  })
  @ApiBody({ type: SetStartModeRequestDto })
  @ApiResponse({ status: 200, type: StartModeResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async put(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<StartModeResponseDto> {
    const { mode } = parseBodyOrThrow(SetStartModeSchema, body);
    const client = await this.tenantDatabaseManager.getClient(auth.tenant.id);
    const s = await this.startMode.set(
      client,
      auth.tenant.id,
      auth.user.id,
      mode,
    );
    return { mode: s.mode };
  }
}
