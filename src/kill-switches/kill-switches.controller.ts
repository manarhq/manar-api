import {
  Body,
  Controller,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
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
import { AgentNotFoundError } from '../agents/agents.errors';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import {
  KillSwitchService,
  TenantKillSwitchScope,
} from './kill-switch.service';
import { PlatformKillSwitchService } from './platform-kill-switch.service';
import { PlatformOperatorGuard } from './platform-operator.guard';
import { ActivateKillSwitchRequestSchema } from './kill-switches.validation';
import {
  ActivateKillSwitchRequestDto,
  KillSwitchDeactivatedResponseDto,
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

  @Post('kill-switches/platform/deactivate')
  @UseGuards(PlatformOperatorGuard)
  @ApiOperation({ summary: 'Deactivate the platform-wide kill switch' })
  @ApiResponse({ status: 201, type: PlatformKillSwitchStatusResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async deactivatePlatform(
    @CurrentAuth() auth: AuthContext,
  ): Promise<PlatformKillSwitchStatusResponseDto> {
    const state = await this.platformKillSwitchService.deactivate(auth.user.id);
    await this.auditPlatformAction(
      auth,
      AUDIT_EVENT_TYPES.KILL_SWITCH_DEACTIVATED,
      {},
    );
    return state;
  }

  // ---------------------------------------------------------------------
  // Tenant scope.
  // ---------------------------------------------------------------------

  @Post('tenants/kill-switch')
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
