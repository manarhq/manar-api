import { Controller, Get, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { PlatformAuthGuard } from '../platform/platform-auth.guard';
import { LicenseStatusDto, TenantLicenseDto } from './license.dto';
import { LicenseService } from './license.service';

/** Full licence status for staff (manar-fleet), on the platform API (ADR-0010). */
@ApiTags('platform')
@ApiBearerAuth('platform')
@UseGuards(PlatformAuthGuard)
@Controller('platform/v1/license')
export class PlatformLicenseController {
  constructor(private readonly license: LicenseService) {}

  @Get()
  @ApiOperation({
    summary:
      'Licence status, claims, limits and usage (soft limits: nothing is blocked)',
  })
  @ApiResponse({ status: 200, type: LicenseStatusDto })
  status(): Promise<LicenseStatusDto> {
    return this.license.status();
  }
}

/**
 * The tenant admin's view, for the console banner. Deployment-wide status only: no customer
 * name, no limits and no usage, so one tenant never sees another's counts.
 */
@ApiTags('tenant-settings')
@ApiBearerAuth('jwt')
@Controller('tenant/license')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
export class TenantLicenseController {
  constructor(private readonly license: LicenseService) {}

  @Get()
  @ApiOperation({
    summary: "This deployment's licence status, for a banner",
    description: 'Requires TENANT_OWNER or SECURITY_ADMIN.',
  })
  @ApiResponse({ status: 200, type: TenantLicenseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async view(): Promise<TenantLicenseDto> {
    const s = await this.license.status();
    return {
      status: s.status,
      deployment: s.deployment,
      expiresAt: s.expiresAt,
      daysLeft: s.daysLeft,
      overLimit: s.overLimit.length > 0,
    };
  }
}
