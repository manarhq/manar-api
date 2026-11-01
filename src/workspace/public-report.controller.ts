import { Controller, Get, Header, Param } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { ReportShareService } from './report-share.service';
import { ReportCardDto } from './workspace.dto';

/**
 * Unauthenticated by design (a shared link). Reads only the control-DB snapshot row, never a
 * tenant database; the global throttler limits it per IP.
 */
@ApiTags('public')
@Controller('public/report')
export class PublicReportController {
  constructor(private readonly shares: ReportShareService) {}

  @Get(':shareId')
  // no-store: a revoked link must stop working at once, not after a cache expires.
  @Header('Cache-Control', 'no-store')
  @Header('X-Robots-Tag', 'noindex')
  @ApiOperation({
    summary: 'Public report card totals',
    description:
      'Totals only: actions, asked you, blocked, secrets kept safe and a 7-day series. Never file names, prompts, device names, emails or workspace names.',
  })
  @ApiResponse({ status: 200, type: ReportCardDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  get(@Param('shareId') shareId: string): Promise<ReportCardDto> {
    return this.shares.publicView(shareId);
  }
}
