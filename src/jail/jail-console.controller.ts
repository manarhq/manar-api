import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { JailSitesService, SiteRuleInputSchema } from './jail-sites.service';

const READ = ['AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const WRITE = ['SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const ID = /^[A-Za-z0-9._:-]{1,128}$/;

/** JAIL, "ask on new sites": what each person allowed or blocked per device and tool. */
@ApiTags('jail')
@ApiBearerAuth('jwt')
@Controller('jail/site-rules')
@UseGuards(JwtAuthGuard, RolesGuard)
export class JailConsoleController {
  constructor(private readonly sites: JailSitesService) {}

  @Get()
  @RequireRole(...READ)
  @ApiOperation({
    summary: 'Site rules of the workspace, optionally one device',
  })
  list(@CurrentAuth() auth: AuthContext, @Query('hostId') hostId?: string) {
    if (hostId !== undefined && !ID.test(hostId))
      throw new BadRequestException('bad id');
    return this.sites.list(auth.tenant.id, hostId);
  }

  @Post()
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Allow or block a site for one tool on one device' })
  create(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    return this.sites.create(
      auth.tenant.id,
      parseBodyOrThrow(SiteRuleInputSchema, body),
      { type: 'human', id: auth.user.id },
    );
  }

  @Delete(':id')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary: 'Remove a site rule: the tool asks again next time',
  })
  remove(@CurrentAuth() auth: AuthContext, @Param('id') id: string) {
    if (!ID.test(id)) throw new BadRequestException('bad id');
    return this.sites.remove(auth.tenant.id, id, {
      type: 'human',
      id: auth.user.id,
    });
  }
}
