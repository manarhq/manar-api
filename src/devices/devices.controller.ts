import { Controller, Post, UseGuards } from '@nestjs/common';
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
import { PlanLimitError } from '../billing/plan-limit.error';
import { DevicesService } from './devices.service';

@ApiTags('devices')
@ApiBearerAuth('jwt')
@Controller('devices')
@UseGuards(JwtAuthGuard, RolesGuard)
export class DevicesController {
  constructor(private readonly devices: DevicesService) {}

  @Post('install-code')
  @RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Add device: a one-hour, single-use install code',
    description:
      'Returns { code, expiresAt, windows, linux, uninstallWindows, uninstallLinux }. The device lands PENDING until approved. 403 plan_limit_reached when the plan has no free device.',
  })
  @ApiResponse({ status: 201, description: 'The code and the one-liners.' })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async installCode(@CurrentAuth() auth: AuthContext) {
    try {
      return await this.devices.createInstallCode(auth);
    } catch (error) {
      if (error instanceof PlanLimitError) throw error;
      throw error;
    }
  }
}
