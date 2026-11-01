import {
  BadRequestException,
  Controller,
  Get,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { HostToolsService } from './host-tools.service';

const READ = ['AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const WRITE = ['SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;

/** The AI tools page: what each device found, how it is protected, and the Protect switch. */
@ApiTags('ai-tools')
@ApiBearerAuth('jwt')
@Controller('ai-tools')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AiToolsController {
  constructor(private readonly tools: HostToolsService) {}

  @Get()
  @RequireRole(...READ)
  @ApiOperation({
    summary:
      'AI tools found on each device, with protection mode and enforcement label',
  })
  list(@CurrentAuth() auth: AuthContext) {
    return this.tools.list(auth.tenant.id);
  }

  @Post(':hostId/:toolId/protect')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Turn protection on for one tool on one device' })
  protect(
    @CurrentAuth() auth: AuthContext,
    @Param('hostId') hostId: string,
    @Param('toolId') toolId: string,
  ) {
    return this.set(auth, hostId, toolId, true);
  }

  @Post(':hostId/:toolId/unprotect')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary:
      "Turn protection off: the device restores that tool's backed-up settings",
  })
  unprotect(
    @CurrentAuth() auth: AuthContext,
    @Param('hostId') hostId: string,
    @Param('toolId') toolId: string,
  ) {
    return this.set(auth, hostId, toolId, false);
  }

  private set(
    auth: AuthContext,
    hostId: string,
    toolId: string,
    desired: boolean,
  ) {
    if (!ID.test(hostId) || !ID.test(toolId))
      return Promise.reject(new BadRequestException('bad id'));
    return this.tools.setDesired(auth.tenant.id, hostId, toolId, desired, {
      type: 'human',
      id: auth.user.id,
    });
  }
}
