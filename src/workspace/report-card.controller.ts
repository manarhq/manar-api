import {
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { ReportCardService } from './report-card.service';
import { ReportShareService } from './report-share.service';
import {
  ReportCardDto,
  ReportShareCreatedDto,
  ReportShareRowDto,
} from './workspace.dto';

/** The caller's own workspace; every query is scoped by `auth.tenant.id`. */
@ApiTags('workspace')
@ApiBearerAuth('jwt')
@Controller('workspace/report-card')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
export class ReportCardController {
  constructor(
    private readonly cards: ReportCardService,
    private readonly shares: ReportShareService,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'This week with your AI: totals and a 7-day series',
  })
  @ApiResponse({ status: 200, type: ReportCardDto })
  get(@CurrentAuth() auth: AuthContext): Promise<ReportCardDto> {
    return this.cards.cardFor(auth.tenant.id);
  }

  @Post('share')
  @ApiOperation({
    summary: 'Share the card',
    description:
      'Creates a public link with an unguessable id. The link shows a snapshot of the totals taken now: no file names, prompts, device names, emails or workspace name.',
  })
  @ApiResponse({ status: 201, type: ReportShareCreatedDto })
  async share(
    @CurrentAuth() auth: AuthContext,
  ): Promise<ReportShareCreatedDto> {
    const totals = await this.cards.refresh(auth.tenant.id);
    return this.shares.create(auth.tenant.id, auth.user.id, totals);
  }

  @Get('shares')
  @ApiOperation({ summary: "List this workspace's report links" })
  @ApiResponse({ status: 200, type: [ReportShareRowDto] })
  list(@CurrentAuth() auth: AuthContext): Promise<ReportShareRowDto[]> {
    return this.shares.list(auth.tenant.id);
  }

  @Delete('shares/:shareId')
  @HttpCode(204)
  @ApiOperation({ summary: 'Revoke a report link' })
  @ApiResponse({ status: 204 })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async revoke(
    @CurrentAuth() auth: AuthContext,
    @Param('shareId') shareId: string,
  ): Promise<void> {
    await this.shares.revoke(auth.tenant.id, shareId);
  }
}
