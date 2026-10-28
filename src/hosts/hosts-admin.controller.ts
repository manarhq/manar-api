import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Patch,
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
import type { HostStatus, InstallKey } from '../generated/tenant-client/client';
import {
  HostNotFoundError,
  HostsAdminService,
  HostTransitionError,
  OrgUnitCycleError,
  type HostDecision,
} from './hosts-admin.service';
import {
  HostGroupNotFoundError,
  InstallKeysService,
  InvalidCidrError,
} from './install-keys.service';
import {
  ApprovalRuleSchema,
  CreateInstallKeySchema,
  HostGroupSchema,
  OrgUnitSchema,
  UpdateApprovalRuleSchema,
  UpdateHostGroupSchema,
  UpdateOrgUnitSchema,
} from './hosts.validation';

const WRITE = ['SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const READ = ['AUDITOR', 'SECURITY_ADMIN', 'TENANT_OWNER'] as const;
const actorOf = (auth: AuthContext): AuditActor => ({
  type: 'human',
  id: auth.user.id,
});

/** An install key as shown: everything but its hash. */
function shown(key: InstallKey): Omit<InstallKey, 'keyHash'> {
  const { keyHash, ...rest } = key;
  void keyHash;
  return rest;
}

/** Maps the hosts domain errors onto HTTP. */
function http(error: unknown): never {
  if (
    error instanceof HostNotFoundError ||
    error instanceof HostGroupNotFoundError
  ) {
    throw new NotFoundException(error.message);
  }
  if (error instanceof HostTransitionError)
    throw new ConflictException(error.message);
  if (error instanceof OrgUnitCycleError || error instanceof InvalidCidrError) {
    throw new BadRequestException(error.message);
  }
  throw error;
}

/** Hosts (docs/hosts.md): list, approve, reject, revoke. */
@ApiTags('hosts')
@ApiBearerAuth('jwt')
@Controller('hosts')
@UseGuards(JwtAuthGuard, RolesGuard)
export class HostsController {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly admin: HostsAdminService,
  ) {}

  @Get()
  @RequireRole(...READ)
  @ApiOperation({ summary: 'List hosts (cursor-paginated, newest first)' })
  @ApiResponse({ status: 200, description: '{ items, nextCursor }' })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async list(
    @CurrentAuth() auth: AuthContext,
    @Query('status') status?: HostStatus,
    @Query('hostGroupId') hostGroupId?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.admin.listHosts(client, {
      status,
      hostGroupId,
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
  }

  @Post(':id/:decision(approve|reject|revoke)')
  @RequireRole(...WRITE)
  @ApiOperation({
    summary: 'Approve, reject or revoke a host',
    description: 'Revoking also revokes its certificates. Audited.',
  })
  @ApiResponse({ status: 201, description: 'The updated host.' })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  @ApiResponse({ status: 409, type: ErrorResponseDto })
  async decide(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Param('decision') decision: HostDecision,
  ) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.admin
      .decide(client, auth.tenant.id, actorOf(auth), id, decision)
      .catch(http);
  }
}

/** Install keys: shown once at creation, never again. */
@ApiTags('hosts')
@ApiBearerAuth('jwt')
@Controller('install-keys')
@UseGuards(JwtAuthGuard, RolesGuard)
export class InstallKeysController {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly keys: InstallKeysService,
  ) {}

  @Get()
  @RequireRole(...READ)
  @ApiOperation({ summary: 'List install keys (never the key itself)' })
  async list(@CurrentAuth() auth: AuthContext) {
    const client = await this.tenants.getClient(auth.tenant.id);
    const rows = await client.installKey.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return rows.map(shown);
  }

  @Post()
  @RequireRole(...WRITE)
  @ApiOperation({
    summary: 'Create an install key',
    description:
      'The key is in this response only, once. Audited (without the key).',
  })
  async create(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(CreateInstallKeySchema, body);
    const client = await this.tenants.getClient(auth.tenant.id);
    const { key, raw } = await this.keys
      .create(client, auth.tenant, actorOf(auth), input)
      .catch(http);
    return { ...shown(key), installKey: raw };
  }

  @Post(':id/revoke')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Revoke an install key (audited)' })
  async revoke(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    const client = await this.tenants.getClient(auth.tenant.id);
    const key = await this.keys.revoke(
      client,
      auth.tenant.id,
      actorOf(auth),
      id,
    );
    if (!key) throw new NotFoundException('install key not found');
    return shown(key);
  }
}

/** Host groups, org units and approval rules. */
@ApiTags('hosts')
@ApiBearerAuth('jwt')
@Controller()
@UseGuards(JwtAuthGuard, RolesGuard)
export class HostOrganisationController {
  constructor(
    private readonly tenants: TenantDatabaseManager,
    private readonly admin: HostsAdminService,
  ) {}

  @Get('host-groups')
  @RequireRole(...READ)
  @ApiOperation({ summary: 'List host groups' })
  async listGroups(@CurrentAuth() auth: AuthContext) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return client.hostGroup.findMany({ orderBy: { name: 'asc' } });
  }

  @Post('host-groups')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Create a host group' })
  async createGroup(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.admin.createHostGroup(
      client,
      parseBodyOrThrow(HostGroupSchema, body),
    );
  }

  @Patch('host-groups/:id')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Rename a host group or change its org unit' })
  async updateGroup(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: unknown,
  ) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.admin.updateHostGroup(
      client,
      id,
      parseBodyOrThrow(UpdateHostGroupSchema, body),
    );
  }

  @Get('org-units')
  @RequireRole(...READ)
  @ApiOperation({ summary: 'List org units (a tree via parentId)' })
  async listOrgUnits(@CurrentAuth() auth: AuthContext) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return client.orgUnit.findMany({ orderBy: { name: 'asc' } });
  }

  @Post('org-units')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Create an org unit' })
  async createOrgUnit(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.admin.createOrgUnit(
      client,
      parseBodyOrThrow(OrgUnitSchema, body),
    );
  }

  @Patch('org-units/:id')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Rename or move an org unit (never under itself)' })
  async updateOrgUnit(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: unknown,
  ) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return this.admin
      .updateOrgUnit(client, id, parseBodyOrThrow(UpdateOrgUnitSchema, body))
      .catch(http);
  }

  @Get('host-approval-rules')
  @RequireRole(...READ)
  @ApiOperation({ summary: 'List host approval rules' })
  async listRules(@CurrentAuth() auth: AuthContext) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return client.hostApprovalRule.findMany({ orderBy: { createdAt: 'asc' } });
  }

  @Post('host-approval-rules')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Create a host approval rule' })
  async createRule(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return Promise.resolve()
      .then(() =>
        this.admin.createApprovalRule(
          client,
          parseBodyOrThrow(ApprovalRuleSchema, body),
        ),
      )
      .catch(http);
  }

  @Patch('host-approval-rules/:id')
  @RequireRole(...WRITE)
  @ApiOperation({ summary: 'Change or disable a host approval rule' })
  async updateRule(
    @CurrentAuth() auth: AuthContext,
    @Param('id', new ParseUUIDPipe()) id: string,
    @Body() body: unknown,
  ) {
    const client = await this.tenants.getClient(auth.tenant.id);
    return Promise.resolve()
      .then(() =>
        this.admin.updateApprovalRule(
          client,
          id,
          parseBodyOrThrow(UpdateApprovalRuleSchema, body),
        ),
      )
      .catch(http);
  }
}
