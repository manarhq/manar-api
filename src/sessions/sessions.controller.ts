import {
  BadRequestException,
  Controller,
  Get,
  Param,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { SessionsService } from './sessions.service';

const ID = /^[A-Za-z0-9_-]{1,512}$/;

/** Agent sessions of the caller's workspace; every query is scoped by `auth.tenant.id`. */
@ApiTags('sessions')
@ApiBearerAuth('jwt')
@Controller('sessions')
@UseGuards(JwtAuthGuard, RolesGuard)
export class SessionsController {
  constructor(private readonly sessions: SessionsService) {}

  @Get()
  @RequireRole('AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Agent sessions per device and tool, newest first',
    description:
      '`source` is `hook` when the tool gave a session id, `gap` when sessions were told apart by 30 quiet minutes.',
  })
  list(
    @CurrentAuth() auth: AuthContext,
    @Query('days') days?: string,
    @Query('hostId') hostId?: string,
    @Query('before') before?: string,
  ) {
    const d = days === undefined ? 14 : Number(days);
    if (!Number.isInteger(d) || d < 1 || d > 30)
      throw new BadRequestException('days must be 1 to 30');
    if (hostId !== undefined && !ID.test(hostId))
      throw new BadRequestException('bad hostId');
    const b = before === undefined ? undefined : new Date(before);
    if (b && Number.isNaN(b.getTime()))
      throw new BadRequestException('bad before');
    return this.sessions.list(auth.tenant.id, d, hostId, b);
  }

  @Get(':id')
  @RequireRole('AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'One session: commands, files, sites and approvals in order',
  })
  get(@CurrentAuth() auth: AuthContext, @Param('id') id: string) {
    if (!ID.test(id)) throw new BadRequestException('bad id');
    return this.sessions.get(auth.tenant.id, id);
  }

  @Post(':id/share')
  @RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Share a redacted copy of one session as a public report link',
    description:
      'Commands show the program only, files the extension only, sites the host only. No device, folder, prompt or person.',
  })
  share(@CurrentAuth() auth: AuthContext, @Param('id') id: string) {
    if (!ID.test(id)) throw new BadRequestException('bad id');
    return this.sessions.share(auth.tenant.id, auth.user.id, id);
  }
}
