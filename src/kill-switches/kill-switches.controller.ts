import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Logger,
  NotFoundException,
  Param,
  Post,
  Query,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { IdempotencyInterceptor } from '../idempotency/idempotency.interceptor';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditEventType } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import { AgentNotFoundError } from '../agents/agents.errors';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { KillSwitchService } from './kill-switch.service';
import type { TenantKillSwitchScope } from './kill-switch.service';
import { PlatformKillSwitchService } from './platform-kill-switch.service';
import { PlatformOperatorGuard } from './platform-operator.guard';
import { ActivateKillSwitchRequestSchema } from './kill-switches.validation';
import {
  ActivateKillSwitchRequestDto,
  KillSwitchDeactivatedResponseDto,
  KillSwitchListResponseDto,
  KillSwitchStatusResponseDto,
  PlatformKillSwitchStatusResponseDto,
} from './kill-switches.dto';

/**
 * Kill-switch phase (Section 32) admin endpoints — see docs/kill-switches.md.
 * `JwtAuthGuard`+`RolesGuard`, gated to `SECURITY_ADMIN`/`TENANT_OWNER`
 * (the same "a role capable of managing agents" bar `AgentsController`/
 * `TasksController` already use — kill switches are at least as
 * security-relevant), for every scope EXCEPT platform, which additionally
 * requires `PlatformOperatorGuard` — see that guard's own doc comment for
 * the full "no application-level super admin" reasoning (Section 11).
 *
 * Every activation/deactivation writes a `kill_switch.activated`/
 * `kill_switch.deactivated` `AuditEvent` via `KillSwitchService`/
 * `PlatformKillSwitchService`'s own callers here — see those methods.
 */
@ApiTags('kill-switches')
@ApiBearerAuth('jwt')
@Controller()
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
export class KillSwitchesController {
  private readonly logger = new Logger(KillSwitchesController.name);

  constructor(
    private readonly killSwitchService: KillSwitchService,
    private readonly platformKillSwitchService: PlatformKillSwitchService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly auditService: AuditService,
  ) {}

  // ---------------------------------------------------------------------
  // Platform scope (control DB, cross-tenant) — see PlatformOperatorGuard.
  // ---------------------------------------------------------------------

  @Post('kill-switches/platform')
  @UseInterceptors(IdempotencyInterceptor)
  @UseGuards(PlatformOperatorGuard)
  @ApiOperation({
    summary: 'Activate the platform-wide kill switch',
    description:
      "Denies EVERY tenant, immediately — the single most destructive lever in the product. Requires SECURITY_ADMIN/TENANT_OWNER in the caller's own tenant AND the separate `X-Platform-Operator-Token` operator credential (see PlatformOperatorGuard).",
  })
  @ApiBody({ type: ActivateKillSwitchRequestDto })
  @ApiResponse({ status: 201, type: PlatformKillSwitchStatusResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async activatePlatform(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<PlatformKillSwitchStatusResponseDto> {
    const input = parseBodyOrThrow(ActivateKillSwitchRequestSchema, body);
    const state = await this.platformKillSwitchService.activate(
      input.reason,
      auth.user.id,
    );
    await this.auditPlatformAction(
      auth,
      AUDIT_EVENT_TYPES.KILL_SWITCH_ACTIVATED,
      {
        reason: input.reason ?? null,
      },
    );
    return state;
  }

  /**
   * Refused (HQ-PLAN section 5, admin v2): turning the platform switch off is a two-person action,
   * proposed in the Manar staff console and applied through `POST /platform/v1/kill-switch/release`
   * for one named engagement. A tenant admin with the operator token could otherwise end any stop
   * alone. Engaging stays open here: stopping must stay easy.
   */
  @Post('kill-switches/platform/deactivate')
  @UseGuards(PlatformOperatorGuard)
  @ApiOperation({
    summary:
      'Refused: the platform kill switch is released only through the two-person flow',
  })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  deactivatePlatform(@CurrentAuth() auth: AuthContext): never {
    this.logger.warn(
      `platform kill switch deactivation refused for ${auth.user.id}: two-person release only`,
    );
    throw new ForbiddenException({
      statusCode: 403,
      code: 'platform_release_requires_two_person',
      message:
        'Turning off the platform kill switch needs two people: propose it in the Manar staff console (Ops, Security) and another person approves it.',
    });
  }

  // ---------------------------------------------------------------------
  // Listing (Phase 11b Part 1) — every tenant-scoped KillSwitch row
  // (TENANT/AGENT_GROUP/AGENT/TOOL), not the separate control-DB
  // PLATFORM singleton (see KillSwitchService.list's own doc comment).
  // ---------------------------------------------------------------------

  @Get('kill-switches')
  @ApiOperation({
    summary: 'List kill switches',
    description:
      'Cursor-paginated, newest first. Optional `scope`/`active` filters. Excludes the platform-wide switch (a control-DB singleton with no id/list semantics of its own).',
  })
  @ApiQuery({
    name: 'scope',
    required: false,
    enum: ['TENANT', 'AGENT_GROUP', 'AGENT', 'TOOL'],
  })
  @ApiQuery({ name: 'active', required: false, type: Boolean })
  @ApiQuery({
    name: 'limit',
    required: false,
    type: Number,
    description: 'Max 100, default 20.',
  })
  @ApiQuery({
    name: 'cursor',
    required: false,
    description: 'Opaque `nextCursor` from a previous page.',
  })
  @ApiResponse({ status: 200, type: KillSwitchListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async list(
    @CurrentAuth() auth: AuthContext,
    @Query('scope') scope?: TenantKillSwitchScope,
    @Query('active') active?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<KillSwitchListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const page = await this.killSwitchService.list(tenantClient, {
      scope,
      active:
        active === undefined ? undefined : active === 'true' || active === '1',
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
    return {
      items: page.items.map((row) => ({
        id: row.id,
        scope: row.scope,
        targetId: row.targetId,
        active: row.active,
        reason: row.reason,
        activatedBy: row.activatedBy,
        activatedAt: row.activatedAt,
        deactivatedBy: row.deactivatedBy,
        deactivatedAt: row.deactivatedAt,
        createdAt: row.createdAt,
      })),
      nextCursor: page.nextCursor,
    };
  }

  // ---------------------------------------------------------------------
  // Tenant scope.
  // ---------------------------------------------------------------------

  @Post('tenants/kill-switch')
  @UseInterceptors(IdempotencyInterceptor)
  @ApiOperation({ summary: "Activate this tenant's kill switch" })
  @ApiBody({ type: ActivateKillSwitchRequestDto })
  @ApiResponse({ status: 201, type: KillSwitchStatusResponseDto })
  async activateTenant(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<KillSwitchStatusResponseDto> {
    return this.activate(auth, 'TENANT', null, body);
  }

  @Post('tenants/kill-switch/deactivate')
  @ApiOperation({ summary: "Deactivate this tenant's kill switch" })
  @ApiResponse({ status: 201, type: KillSwitchDeactivatedResponseDto })
  async deactivateTenant(
    @CurrentAuth() auth: AuthContext,
  ): Promise<KillSwitchDeactivatedResponseDto> {
    return this.deactivate(auth, 'TENANT', null);
  }

  // ---------------------------------------------------------------------
  // Agent-group scope.
  // ---------------------------------------------------------------------

  @Post('agent-groups/:id/kill-switch')
  @UseInterceptors(IdempotencyInterceptor)
  @ApiOperation({ summary: "Activate an agent group's kill switch" })
  @ApiParam({ name: 'id', description: 'AgentGroup ID', format: 'uuid' })
  @ApiBody({ type: ActivateKillSwitchRequestDto })
  @ApiResponse({ status: 201, type: KillSwitchStatusResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async activateAgentGroup(
    @CurrentAuth() auth: AuthContext,
    @Param('id') groupId: string,
    @Body() body: unknown,
  ): Promise<KillSwitchStatusResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const group = await tenantClient.agentGroup.findUnique({
      where: { id: groupId },
    });
    if (!group)
      throw new NotFoundException(`AgentGroup "${groupId}" was not found`);
    return this.activate(auth, 'AGENT_GROUP', groupId, body);
  }

  @Post('agent-groups/:id/kill-switch/deactivate')
  @ApiOperation({ summary: "Deactivate an agent group's kill switch" })
  @ApiParam({ name: 'id', description: 'AgentGroup ID', format: 'uuid' })
  @ApiResponse({ status: 201, type: KillSwitchDeactivatedResponseDto })
  async deactivateAgentGroup(
    @CurrentAuth() auth: AuthContext,
    @Param('id') groupId: string,
  ): Promise<KillSwitchDeactivatedResponseDto> {
    return this.deactivate(auth, 'AGENT_GROUP', groupId);
  }

  // ---------------------------------------------------------------------
  // Agent scope.
  // ---------------------------------------------------------------------

  @Post('agents/:id/kill-switch')
  @UseInterceptors(IdempotencyInterceptor)
  @ApiOperation({ summary: "Activate an agent's kill switch" })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  @ApiBody({ type: ActivateKillSwitchRequestDto })
  @ApiResponse({ status: 201, type: KillSwitchStatusResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async activateAgent(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Body() body: unknown,
  ): Promise<KillSwitchStatusResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const agent = await tenantClient.agent.findUnique({
      where: { id: agentId },
    });
    if (!agent)
      throw new NotFoundException(new AgentNotFoundError(agentId).message);
    return this.activate(auth, 'AGENT', agentId, body);
  }

  @Post('agents/:id/kill-switch/deactivate')
  @ApiOperation({ summary: "Deactivate an agent's kill switch" })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  @ApiResponse({ status: 201, type: KillSwitchDeactivatedResponseDto })
  async deactivateAgent(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
  ): Promise<KillSwitchDeactivatedResponseDto> {
    return this.deactivate(auth, 'AGENT', agentId);
  }

  // ---------------------------------------------------------------------
  // Tool scope.
  // ---------------------------------------------------------------------

  @Post('tools/:id/kill-switch')
  @UseInterceptors(IdempotencyInterceptor)
  @ApiOperation({ summary: "Activate a tool's kill switch" })
  @ApiParam({ name: 'id', description: 'Tool ID', format: 'uuid' })
  @ApiBody({ type: ActivateKillSwitchRequestDto })
  @ApiResponse({ status: 201, type: KillSwitchStatusResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async activateTool(
    @CurrentAuth() auth: AuthContext,
    @Param('id') toolId: string,
    @Body() body: unknown,
  ): Promise<KillSwitchStatusResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const tool = await tenantClient.tool.findUnique({ where: { id: toolId } });
    if (!tool) throw new NotFoundException(`Tool "${toolId}" was not found`);
    return this.activate(auth, 'TOOL', toolId, body);
  }

  @Post('tools/:id/kill-switch/deactivate')
  @ApiOperation({ summary: "Deactivate a tool's kill switch" })
  @ApiParam({ name: 'id', description: 'Tool ID', format: 'uuid' })
  @ApiResponse({ status: 201, type: KillSwitchDeactivatedResponseDto })
  async deactivateTool(
    @CurrentAuth() auth: AuthContext,
    @Param('id') toolId: string,
  ): Promise<KillSwitchDeactivatedResponseDto> {
    return this.deactivate(auth, 'TOOL', toolId);
  }

  // ---------------------------------------------------------------------
  // Shared helpers.
  // ---------------------------------------------------------------------

  private async activate(
    auth: AuthContext,
    scope: TenantKillSwitchScope,
    targetId: string | null,
    body: unknown,
  ): Promise<KillSwitchStatusResponseDto> {
    const input = parseBodyOrThrow(ActivateKillSwitchRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const row = await this.killSwitchService.activate(
      tenantClient,
      auth.tenant.id,
      {
        scope,
        targetId,
        reason: input.reason,
        activatedBy: auth.user.id,
      },
    );
    return {
      id: row.id,
      scope: row.scope,
      targetId: row.targetId,
      active: row.active,
      reason: row.reason,
      activatedAt: row.activatedAt,
    };
  }

  private async deactivate(
    auth: AuthContext,
    scope: TenantKillSwitchScope,
    targetId: string | null,
  ): Promise<KillSwitchDeactivatedResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    await this.killSwitchService.deactivate(tenantClient, auth.tenant.id, {
      scope,
      targetId,
      deactivatedBy: auth.user.id,
    });
    return { status: 'INACTIVE' };
  }

  /**
   * The platform switch's own row lives in the control DB (no tenant, no
   * `UserProfile` FK there — see `PlatformKillSwitch`'s schema doc
   * comment), but the calling human is still a real, tenant-affiliated
   * `AuthContext` — recorded into *that* tenant's own audit chain (the
   * normal per-request `tenantClient`/`tenantId` this codebase already
   * uses everywhere else), exactly like any other action a tenant's user
   * takes. This is a record of "this tenant's user pulled the
   * platform-wide lever," not a (nonexistent) cross-tenant audit chain.
   */
  private async auditPlatformAction(
    auth: AuthContext,
    eventType: AuditEventType,
    data: Record<string, unknown>,
  ): Promise<void> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    await this.auditService.recordSafely(tenantClient, auth.tenant.id, {
      eventType,
      actor: { type: 'human', id: auth.user.id },
      data: { scope: 'PLATFORM', targetId: null, ...data },
    });
  }
}
