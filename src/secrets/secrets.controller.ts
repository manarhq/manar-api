import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import type { AuditActor } from '../audit/audit-event-types';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import {
  SecretsConflictError,
  SecretsNotFoundError,
  SecretsService,
} from './secrets.service';
import {
  AccessDecisionSchema,
  SECRET_EVENT_TYPES,
  VaultRequestSchema,
} from './secrets.validation';

const READ = ['AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const WRITE = ['SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const actorOf = (auth: AuthContext): AuditActor => ({
  type: 'human',
  id: auth.user.id,
});

function http(error: unknown): never {
  if (error instanceof SecretsNotFoundError)
    throw new NotFoundException(error.message);
  if (error instanceof SecretsConflictError)
    throw new ConflictException(error.message);
  throw error;
}

function dateParam(raw: string | undefined, name: string): Date | undefined {
  if (raw === undefined) return undefined;
  const d = new Date(raw);
  if (Number.isNaN(d.getTime()))
    throw new BadRequestException(
      `Invalid "${name}": use an ISO-8601 date-time`,
    );
  return d;
}

/** Secrets page: the timeline, what each tool touched, and the Secret vault. */
@ApiTags('secrets')
@ApiBearerAuth('jwt')
@Controller('secrets')
@UseGuards(JwtAuthGuard, RolesGuard)
export class SecretsController {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly secrets: SecretsService,
  ) {}

  @Get('timeline')
  @RequireRole(...READ)
  @ApiOperation({
    summary: 'Secrets timeline (cursor-paginated, newest first)',
    description:
      'Filter by hostId, toolId (host.cursor), type (secret.touched) and from/to. Paths have the home directory masked.',
  })
  @ApiResponse({ status: 200, description: '{ items, nextCursor }' })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async timeline(
    @CurrentAuth() auth: AuthContext,
    @Query('hostId') hostId?: string,
    @Query('toolId') toolId?: string,
    @Query('type') type?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ) {
    if (hostId !== undefined && !/^[0-9a-f-]{36}$/i.test(hostId))
      throw new BadRequestException('Invalid "hostId"');
    if (toolId !== undefined && !/^(host\.[a-z0-9-]{1,40}|other)$/.test(toolId))
      throw new BadRequestException('Invalid "toolId"');
    if (
      type !== undefined &&
      !(SECRET_EVENT_TYPES as readonly string[]).includes(type)
    )
      throw new BadRequestException('Invalid "type"');
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.secrets.timeline(client, {
      hostId,
      toolId,
      type,
      from: dateParam(from, 'from'),
      to: dateParam(to, 'to'),
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
  }

  @Get('overview')
  @RequireRole(...READ)
  @ApiOperation({
    summary: 'What each AI tool touched, watcher status and vault per device',
    description:
      'Watcher status is ok, monitoring unavailable, or unknown (no report yet).',
  })
  async overview(
    @CurrentAuth() auth: AuthContext,
    @Query('days') days?: string,
  ) {
    const n = Math.min(Math.max(Number.parseInt(days ?? '7', 10) || 7, 1), 90);
    return this.secrets.overview(
      await this.tenants.getClient(auth.tenant.id),
      n,
    );
  }

  @Post('vault/:hostId')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary: 'Protect one secret in the device vault',
    description:
      'Body { kind: "aws"|"ssh", ref }. The device moves the secret, verifies it, and reports back. Audited when stored.',
  })
  @ApiResponse({
    status: 201,
    description: 'The vault entry (state REQUESTED).',
  })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  @ApiResponse({ status: 409, type: ErrorResponseDto })
  async vault(
    @CurrentAuth() auth: AuthContext,
    @Param('hostId', new ParseUUIDPipe()) hostId: string,
    @Body() body: unknown,
  ) {
    const b = parseBodyOrThrow(VaultRequestSchema, body);
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.secrets
      .requestVault(
        client,
        auth.tenant.id,
        actorOf(auth),
        hostId,
        b.kind,
        b.ref,
      )
      .catch(http);
  }

  @Post('vault/:hostId/restore')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary: 'Restore one vaulted secret to its file, exactly as it was',
  })
  @ApiResponse({
    status: 201,
    description: 'The vault entry (state RESTORE_REQUESTED).',
  })
  @ApiResponse({ status: 409, type: ErrorResponseDto })
  async restore(
    @CurrentAuth() auth: AuthContext,
    @Param('hostId', new ParseUUIDPipe()) hostId: string,
    @Body() body: unknown,
  ) {
    const b = parseBodyOrThrow(VaultRequestSchema, body);
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.secrets
      .requestRestore(
        client,
        auth.tenant.id,
        actorOf(auth),
        hostId,
        b.kind,
        b.ref,
      )
      .catch(http);
  }

  @Get('access')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Programs waiting for a vaulted secret' })
  async access(@CurrentAuth() auth: AuthContext) {
    return this.secrets.listAccess(
      await this.tenants.getClient(auth.tenant.id),
    );
  }

  @Post('access/:id/decide')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary: 'Allow once, 8 hours, always for this program, or deny',
    description:
      'Body { decision: "ALLOW_ONCE"|"ALLOW_8H"|"ALLOW_ALWAYS"|"DENY" }. Audited as secret.vault.released or secret.vault.denied.',
  })
  @ApiResponse({ status: 409, type: ErrorResponseDto })
  async decide(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: unknown,
  ) {
    const b = parseBodyOrThrow(AccessDecisionSchema, body);
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.secrets
      .decideAccess(client, auth.tenant.id, actorOf(auth), id, b.decision)
      .catch(http);
  }
}
