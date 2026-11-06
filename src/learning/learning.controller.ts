import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { APPROVER_ROLES } from '../approvals/approver-directory';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { LearningService } from './learning.service';

const DeviceSchema = z
  .object({ action: z.enum(['off', 'on', 'restart']) })
  .strict();

/** "Here is what Manar saw this week" (decision 36). The caller's own workspace only. */
@ApiTags('workspace')
@ApiBearerAuth('jwt')
@Controller('workspace/learning')
@UseGuards(JwtAuthGuard, RolesGuard)
export class LearningController {
  constructor(
    private readonly learning: LearningService,
    private readonly tenants: TenantDatabaseManager,
  ) {}

  @Get()
  @RequireRole(...APPROVER_ROLES)
  @ApiOperation({
    summary:
      'What Manar saw while new devices learned, and the rules it suggests',
    description:
      'Devices still learning (until when), how many actions would have asked, and suggestions seen 3 or more times. Nothing here is a prompt: it is a page the person opens.',
  })
  async summary(@CurrentAuth() auth: AuthContext) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.learning.summary(client, auth.tenant.id);
  }

  @Post('suggestions/:id/accept')
  @HttpCode(200)
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({
    summary: 'Accept a suggestion: always allow this here',
    description:
      'Creates a one-year, device-scoped, narrow "always allow" (origin learning). Withdraw it with POST /approvals/allow-grants/:id/revoke.',
  })
  async accept(
    @CurrentAuth() auth: AuthContext,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.learning.accept(client, auth.tenant.id, id, {
      id: auth.user.id,
    });
  }

  @Post('suggestions/:id/dismiss')
  @HttpCode(200)
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({ summary: 'Not now: hide a suggestion' })
  async dismiss(
    @CurrentAuth() auth: AuthContext,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.learning.dismiss(client, auth.tenant.id, id, {
      id: auth.user.id,
    });
  }

  @Put('devices/:hostId')
  @RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
  @ApiOperation({
    summary: 'Turn learning off or on for one device, or restart its 7 days',
  })
  async device(
    @CurrentAuth() auth: AuthContext,
    @Param('hostId', ParseUUIDPipe) hostId: string,
    @Body() body: unknown,
  ) {
    const { action } = parseBodyOrThrow(DeviceSchema, body);
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.learning.setDevice(client, auth.tenant.id, hostId, action, {
      id: auth.user.id,
    });
  }
}
