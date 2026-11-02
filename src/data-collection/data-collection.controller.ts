import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { CurrentAuth, type AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { DataCollectionService } from './data-collection.service';
import {
  ConsoleEventsBody,
  CONSOLE_EVENTS,
  FlagsPatch,
  MyPrefsPatch,
} from './data-collection.dto';

/** Product improvement data: the caller's own switches and the console event intake. */
@ApiTags('data-collection')
@ApiBearerAuth('jwt')
@Controller()
@UseGuards(JwtAuthGuard)
export class DataCollectionController {
  constructor(private readonly data: DataCollectionService) {}

  @Get('me/data-preferences')
  @ApiOperation({
    summary: 'Your product improvement data switches',
    description:
      "improveManar and aiTraining (both default on); org is the workspace's pair for company workspaces, else null; effective = yours AND the workspace's (aiTraining is off while improveManar is off).",
  })
  mine(@CurrentAuth() auth: AuthContext) {
    return this.data.getMine(
      auth.issuer,
      auth.user.keycloakSubject,
      auth.tenant.id,
    );
  }

  @Put('me/data-preferences')
  @ApiOperation({
    summary: 'Change your product improvement data switches',
    description:
      'Body { improveManar?, aiTraining?, noticeDismissed? }. Turning improveManar off deletes your stored samples at once and asks PostHog to delete your person.',
  })
  setMine(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    return this.data.setMine(
      auth.issuer,
      auth.user.keycloakSubject,
      auth.tenant.id,
      parseBodyOrThrow(MyPrefsPatch, body),
    );
  }

  @Post('telemetry/events')
  @HttpCode(204)
  @Throttle({ human: { limit: 120, ttl: 60_000 } })
  @ApiOperation({
    summary: 'Console usage events (product improvement data)',
    description: `Body { events: [{ name, at, props }] }: at most 50 events; name one of ${CONSOLE_EVENTS.join(', ')}; props primitives only, at most 20 keys, strings at most 200 chars. 204 whether forwarded or dropped (switch off, PostHog not configured).`,
  })
  async events(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const { events } = parseBodyOrThrow(ConsoleEventsBody, body);
    await this.data.ingestConsole(
      auth.issuer,
      auth.user.keycloakSubject,
      auth.tenant.id,
      events,
    );
  }
}

/** The workspace's pair of switches: company workspaces, managers only. */
@ApiTags('data-collection')
@ApiBearerAuth('jwt')
@Controller('workspace/data-preferences')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('TENANT_OWNER', 'SECURITY_ADMIN')
export class WorkspaceDataPreferencesController {
  constructor(private readonly data: DataCollectionService) {}

  private company(auth: AuthContext) {
    if (auth.workspaceKind !== 'COMPANY')
      throw new ForbiddenException('company_workspace_only');
  }

  @Get()
  @ApiOperation({ summary: 'Workspace product improvement data switches' })
  get(@CurrentAuth() auth: AuthContext) {
    this.company(auth);
    return this.data.getOrg(auth.tenant.id);
  }

  @Put()
  @ApiOperation({
    summary: 'Change the workspace switches (audit logged)',
    description:
      "Body { improveManar?, aiTraining? }. Off overrides every member. Turning improveManar off deletes the workspace's stored samples.",
  })
  set(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    this.company(auth);
    return this.data.setOrg(
      auth.tenant.id,
      auth.user.keycloakSubject,
      parseBodyOrThrow(FlagsPatch, body),
    );
  }
}
