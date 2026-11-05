import {
  Body,
  Controller,
  Get,
  HttpCode,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
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
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { TenantSettingsService } from './tenant-settings.service';
import { UpdateTenantSettingsSchema } from './tenant-settings.validation';
import {
  TenantSettingsResponseDto,
  UpdateTenantSettingsRequestDto,
} from './tenant-settings.dto';

/**
 * `GET`/`PATCH /tenant/settings` — Phase 14's tenant-settings surface,
 * backing `manar-web`'s `/settings/security`, `/settings/sso`,
 * `/settings/residency`, `/settings/ai` pages. Always the caller's own
 * tenant (`auth.tenant.id`) — there is no tenant id in the URL, matching
 * Section 23's "never trust a client-supplied tenant id" rule. Gated to
 * `TENANT_OWNER`/`SECURITY_ADMIN` for both reads and writes, per this
 * phase's design spec (these are security/residency/SSO-adjacent
 * settings, not general operational data every tenant member should be
 * able to see).
 */
@ApiTags('tenant-settings')
@ApiBearerAuth('jwt')
@Controller('tenant/settings')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
export class TenantSettingsController {
  constructor(private readonly tenantSettingsService: TenantSettingsService) {}

  @Get()
  @ApiOperation({
    summary: "Get the caller's tenant settings",
    description:
      'Residency/AI-governance flags (Phase 2), plus read-only SSO/AI-provider/rate-limit info. Requires TENANT_OWNER or SECURITY_ADMIN.',
  })
  @ApiResponse({ status: 200, type: TenantSettingsResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async getSettings(
    @CurrentAuth() auth: AuthContext,
  ): Promise<TenantSettingsResponseDto> {
    return this.tenantSettingsService.getSettings(auth.tenant.id);
  }

  @Patch()
  @ApiOperation({
    summary: "Update the caller's tenant settings",
    description:
      'Partial update -- only residency/allowExternalAi/allowOutboundTelemetry/allowCloudStorage/approvalsAdminsOnly (company workspaces) are writable; every other field GET returns is read-only. Requires TENANT_OWNER or SECURITY_ADMIN. Audited. allowExternalAi takes effect immediately on the very next AI-advisory-eligible request (AiAdvisoryClient reads the live Tenant row, no caching).',
  })
  @ApiBody({ type: UpdateTenantSettingsRequestDto })
  @ApiResponse({ status: 200, type: TenantSettingsResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async updateSettings(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<TenantSettingsResponseDto> {
    const input = parseBodyOrThrow(UpdateTenantSettingsSchema, body);
    return this.tenantSettingsService.updateSettings(
      auth.tenant.id,
      auth.user.id,
      input,
    );
  }

  @Post('ai-default-notice/dismiss')
  @HttpCode(204)
  @ApiOperation({
    summary: 'Dismiss the one-time "AI is now on" notice',
    description:
      'Clears `aiDefaultNoticePending` for the workspace. Requires TENANT_OWNER or SECURITY_ADMIN. Idempotent.',
  })
  @ApiResponse({ status: 204 })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async dismissAiDefaultNotice(
    @CurrentAuth() auth: AuthContext,
  ): Promise<void> {
    await this.tenantSettingsService.dismissAiDefaultNotice(auth.tenant.id);
  }
}
