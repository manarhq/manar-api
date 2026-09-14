import {
  Body,
  ConflictException,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  NotFoundException,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
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
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import {
  AiSystemInvalidTransitionError,
  AiSystemNotFoundError,
  AiSystemReferenceNotFoundError,
  AiSystemRetiredError,
  AiSystemSeparationOfDutiesError,
  AiSystemSlugConflictError,
} from './ai-systems.errors';
import {
  AiSystemsService,
  type AiSystemEnvironment,
  type AiSystemLifecycleState,
} from './ai-systems.service';
import {
  CreateAiSystemSchema,
  LinkAgentSchema,
  LinkToolSchema,
  TransitionAiSystemSchema,
  UpdateAiSystemSchema,
} from './ai-systems.validation';
import {
  AiSystemDetailDto,
  AiSystemLinkResultDto,
  AiSystemListResponseDto,
  AiSystemSummaryDto,
  AiSystemTransitionDto,
  AiSystemVersionDto,
  CreateAiSystemRequestDto,
  LinkAgentRequestDto,
  LinkToolRequestDto,
  TransitionAiSystemRequestDto,
  UpdateAiSystemRequestDto,
} from './ai-systems.dto';

/**
 * Translates `AiSystemsService`'s typed domain errors into HTTP responses
 * — the same `mapXErrors` convention `IncidentsController`/
 * `UsersController` established.
 *
 * The mapping is deliberately specific rather than collapsing everything
 * into 400/409: an operator who is told "this transition is not allowed"
 * and an operator who is told "someone else has to do this" need to take
 * different actions, and a shared status code with a generic body would
 * hide that difference in exactly the workflow where it matters most.
 */
async function mapAiSystemErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (
      error instanceof AiSystemNotFoundError ||
      error instanceof AiSystemReferenceNotFoundError
    ) {
      throw new NotFoundException(error.message);
    }
    if (
      error instanceof AiSystemSlugConflictError ||
      error instanceof AiSystemInvalidTransitionError ||
      error instanceof AiSystemRetiredError
    ) {
      throw new ConflictException(error.message);
    }
    if (error instanceof AiSystemSeparationOfDutiesError) {
      throw new ForbiddenException(error.message);
    }
    throw error;
  }
}

/**
 * Release 2026-11-11 (brief §3.1) — `/ai-systems`, the governed
 * AI-system/use-case inventory.
 *
 * **Role posture.** Reads are open to any authenticated tenant user: an
 * auditor or approver needs to see what a system is and who owns it in
 * order to do their own job, and hiding the inventory from them would push
 * that context into side channels. Writes require
 * `AI_GOVERNANCE_MANAGER`, `SECURITY_ADMIN`, or `TENANT_OWNER` — this is
 * the governance manager's primary record, and an arbitrary tenant user
 * being able to declare a production AI system (or retire one) would make
 * the inventory unusable as evidence. This is a coarse endpoint-level gate
 * (`RolesGuard`); resource-scoped authorization remains OpenFGA's job.
 */
@ApiTags('ai-systems')
@ApiBearerAuth('jwt')
@Controller('ai-systems')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AiSystemsController {
  constructor(
    private readonly aiSystemsService: AiSystemsService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post()
  @RequireRole('AI_GOVERNANCE_MANAGER', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Register an AI system',
    description:
      'Always created in DRAFT — the caller cannot choose a starting lifecycle state, because every other state is meant to be the result of a recorded transition. Audited (ai_system.created).',
  })
  @ApiBody({ type: CreateAiSystemRequestDto })
  @ApiResponse({ status: 201, type: AiSystemSummaryDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'ownerId does not resolve to a user in this tenant.',
  })
  @ApiResponse({
    status: 409,
    type: ErrorResponseDto,
    description: 'slug already exists in this tenant.',
  })
  async create(
    @CurrentAuth() auth: AuthContext,
    @Body() body: unknown,
  ): Promise<AiSystemSummaryDto> {
    const input = parseBodyOrThrow(CreateAiSystemSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.createAiSystem(tenantClient, {
        ...input,
        tenantId: auth.tenant.id,
        createdByUserId: auth.user.id,
      }),
    );
  }

  @Get()
  @ApiOperation({
    summary: 'List AI systems',
    description:
      'Cursor-paginated, newest first. Note there is deliberately no `coverage` filter: coverage is derived per record from live observations, so filtering on it server-side would either require deriving it for every row in the tenant or silently filtering only the current page — both of which would make the returned counts untrustworthy.',
  })
  @ApiQuery({
    name: 'lifecycleState',
    required: false,
    enum: ['DRAFT', 'REVIEW', 'ACTIVE', 'SUSPENDED', 'RETIRED'],
  })
  @ApiQuery({
    name: 'environment',
    required: false,
    enum: ['DEVELOPMENT', 'STAGING', 'PRODUCTION'],
  })
  @ApiQuery({ name: 'ownerId', required: false, format: 'uuid' })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'cursor', required: false })
  @ApiResponse({ status: 200, type: AiSystemListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  async list(
    @CurrentAuth() auth: AuthContext,
    @Query('lifecycleState') lifecycleState?: string,
    @Query('environment') environment?: string,
    @Query('ownerId') ownerId?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<AiSystemListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return this.aiSystemsService.listAiSystems(tenantClient, {
      lifecycleState: lifecycleState as AiSystemLifecycleState | undefined,
      environment: environment as AiSystemEnvironment | undefined,
      ownerId,
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
  }

  @Get(':id')
  @ApiOperation({
    summary: 'Get one AI system, with derived coverage',
    description:
      'coverage is computed per request from real ToolInvocation rows and Agent.status — it is never stored. MONITORING_UNAVAILABLE means the observation source could not be consulted; it never means "no activity".',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiResponse({ status: 200, type: AiSystemDetailDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async get(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<AiSystemDetailDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.getAiSystemOrThrow(tenantClient, id),
    );
  }

  @Patch(':id')
  @RequireRole('AI_GOVERNANCE_MANAGER', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Update an AI system’s governed fields',
    description:
      'Every field here is material: the prior state is snapshotted into the version history and `version` is incremented, in the same transaction as the update. `lifecycleState` cannot be changed here — use POST /ai-systems/:id/transitions. Audited (ai_system.updated).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ type: UpdateAiSystemRequestDto })
  @ApiResponse({ status: 200, type: AiSystemSummaryDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  @ApiResponse({
    status: 409,
    type: ErrorResponseDto,
    description: 'The system is RETIRED and can no longer be modified.',
  })
  async update(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<AiSystemSummaryDto> {
    const input = parseBodyOrThrow(UpdateAiSystemSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.updateAiSystem(tenantClient, {
        ...input,
        tenantId: auth.tenant.id,
        aiSystemId: id,
        actorUserId: auth.user.id,
      }),
    );
  }

  @Post(':id/transitions')
  @RequireRole('AI_GOVERNANCE_MANAGER', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Move an AI system through its lifecycle',
    description:
      'The only path that changes lifecycleState. Rejects any edge outside the allowed-transition table with 409. REVIEW→ACTIVE additionally requires a different user than the one who submitted the system for review (403 otherwise) — the review state is meaningless if one person can walk a record through it alone. Audited (ai_system.state_changed).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ type: TransitionAiSystemRequestDto })
  @ApiResponse({ status: 201, type: AiSystemSummaryDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({
    status: 403,
    type: ErrorResponseDto,
    description:
      'Insufficient role, or separation of duties: the same user submitted this system for review.',
  })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  @ApiResponse({
    status: 409,
    type: ErrorResponseDto,
    description: 'Not an allowed lifecycle edge from the current state.',
  })
  async transition(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<AiSystemSummaryDto> {
    const input = parseBodyOrThrow(TransitionAiSystemSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.transitionState(tenantClient, {
        ...input,
        tenantId: auth.tenant.id,
        aiSystemId: id,
        actorUserId: auth.user.id,
      }),
    );
  }

  @Get(':id/versions')
  @ApiOperation({
    summary: 'The AI system’s material-change history',
    description:
      'Newest first. Each entry is the full governed field set as it stood before the change that superseded it, plus who changed it and why.',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiResponse({ status: 200, type: AiSystemVersionDto, isArray: true })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async versions(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<AiSystemVersionDto[]> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.listVersions(tenantClient, id),
    ) as Promise<AiSystemVersionDto[]>;
  }

  @Get(':id/transitions')
  @ApiOperation({ summary: 'The AI system’s lifecycle history' })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiResponse({ status: 200, type: AiSystemTransitionDto, isArray: true })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async transitions(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<AiSystemTransitionDto[]> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.listTransitions(tenantClient, id),
    );
  }

  @Post(':id/agents')
  @RequireRole('AI_GOVERNANCE_MANAGER', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Link an existing agent to this AI system',
    description:
      'An additive, attributed, reversible assertion. It never rewrites the agent’s own ownership fields, and it does not by itself change what is enforced for that agent. Re-linking an already-linked agent returns linked:false rather than 409, so a retried request is unambiguous. Audited (ai_system.agent_linked).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ type: LinkAgentRequestDto })
  @ApiResponse({ status: 201, type: AiSystemLinkResultDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  @ApiResponse({ status: 409, type: ErrorResponseDto })
  async linkAgent(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<AiSystemLinkResultDto> {
    const input = parseBodyOrThrow(LinkAgentSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.linkAgent(tenantClient, {
        tenantId: auth.tenant.id,
        aiSystemId: id,
        agentId: input.agentId,
        actorUserId: auth.user.id,
      }),
    );
  }

  @Delete(':id/agents/:agentId')
  @RequireRole('AI_GOVERNANCE_MANAGER', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Unlink an agent from this AI system',
    description: 'Audited (ai_system.agent_unlinked).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiParam({ name: 'agentId', format: 'uuid' })
  @ApiResponse({ status: 200, type: AiSystemLinkResultDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async unlinkAgent(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Param('agentId') agentId: string,
  ): Promise<AiSystemLinkResultDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.unlinkAgent(tenantClient, {
        tenantId: auth.tenant.id,
        aiSystemId: id,
        agentId,
        actorUserId: auth.user.id,
      }),
    );
  }

  @Post(':id/tools')
  @RequireRole('AI_GOVERNANCE_MANAGER', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Link a registered tool to this AI system',
    description: 'Audited (ai_system.tool_linked).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ type: LinkToolRequestDto })
  @ApiResponse({ status: 201, type: AiSystemLinkResultDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async linkTool(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<AiSystemLinkResultDto> {
    const input = parseBodyOrThrow(LinkToolSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.linkTool(tenantClient, {
        tenantId: auth.tenant.id,
        aiSystemId: id,
        toolId: input.toolId,
        actorUserId: auth.user.id,
      }),
    );
  }

  @Delete(':id/tools/:toolId')
  @RequireRole('AI_GOVERNANCE_MANAGER', 'SECURITY_ADMIN', 'TENANT_OWNER')
  @ApiOperation({
    summary: 'Unlink a tool from this AI system',
    description: 'Audited (ai_system.tool_unlinked).',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiParam({ name: 'toolId', format: 'uuid' })
  @ApiResponse({ status: 200, type: AiSystemLinkResultDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async unlinkTool(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Param('toolId') toolId: string,
  ): Promise<AiSystemLinkResultDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return mapAiSystemErrors(() =>
      this.aiSystemsService.unlinkTool(tenantClient, {
        tenantId: auth.tenant.id,
        aiSystemId: id,
        toolId,
        actorUserId: auth.user.id,
      }),
    );
  }
}
