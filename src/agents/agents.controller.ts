import {
  Body,
  ConflictException,
  Controller,
  Get,
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
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import {
  AgentNotFoundError,
  AgentTerminatedError,
  CloudAgentOperationError,
} from './agents.errors';
import { EntitlementsService } from '../billing/entitlements.service';
import { AgentsService } from './agents.service';
import {
  CreateAgentRequestSchema,
  RevokeAgentRequestSchema,
} from './agents.validation';
import {
  AgentListResponseDto,
  CreateAgentRequestDto,
  CreateAgentResponseDto,
  CreateEnrollmentTokenResponseDto,
  RevokeAgentRequestDto,
  RevokeStatusResponseDto,
} from './agents.dto';
import { parseBodyOrThrow } from './parse-body.util';

/** Translates the service layer's typed domain errors into HTTP responses, keeping controller methods free of repeated try/catch. */
async function mapAgentNotFound<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof AgentNotFoundError) {
      throw new NotFoundException(error.message);
    }
    if (error instanceof AgentTerminatedError) {
      throw new ConflictException(error.message);
    }
    if (error instanceof CloudAgentOperationError) {
      throw new ConflictException(error.message);
    }
    throw error;
  }
}

/**
 * Human-facing agent management (Section 14) — creating an agent record,
 * issuing it an enrollment token, and revoking it. Gated by
 * `JwtAuthGuard`+`RolesGuard` like every other authenticated surface (see
 * docs/human-auth.md); `SECURITY_ADMIN`/`TENANT_OWNER` were chosen as "a
 * role capable of managing agents" (the design spec's own phrasing) since
 * agents are security principals — the same class of decision
 * `RolesGuard`'s existing `SECURITY_ADMIN`-gated example endpoint models.
 *
 * Distinct from `AgentEnrollController` (`POST /agents/enroll`), which is
 * deliberately *unauthenticated* — an enrolling agent has no JWT yet, only
 * a one-time enrollment token minted by this controller.
 */
@ApiTags('agents')
@ApiBearerAuth('jwt')
@Controller('agents')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER')
export class AgentsController {
  constructor(
    private readonly agentsService: AgentsService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly entitlements: EntitlementsService,
  ) {}

  @Post()
  @UseInterceptors(IdempotencyInterceptor)
  @ApiOperation({
    summary: 'Create an agent record',
    description:
      'Creates the Agent row in `PENDING_ENROLLMENT` status. Does not itself issue an enrollment token — call `POST /agents/:id/enrollment-tokens` next. Requires SECURITY_ADMIN or TENANT_OWNER. Supports an `Idempotency-Key` header (Phase 12a, Section 8) — a replay with the same key returns the original response without creating a second Agent row.',
  })
  @ApiBody({ type: CreateAgentRequestDto })
  @ApiResponse({ status: 201, type: CreateAgentResponseDto })
  @ApiResponse({
    status: 400,
    type: ErrorResponseDto,
    description: 'Invalid request body.',
  })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async createAgent(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(CreateAgentRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    // Plan cap: live agents other than cloud agents (those have their own cap).
    await this.entitlements.assertWithin(
      auth.tenant.id,
      'agents',
      await tenantClient.agent.count({
        where: {
          status: { in: ['PENDING_ENROLLMENT', 'ACTIVE'] },
          cloudBinding: null,
        },
      }),
    );

    const agent = await this.agentsService.createAgent(tenantClient, {
      slug: input.slug,
      displayName: input.displayName,
      tenantSlug: auth.tenant.slug,
      createdBy: auth.user.id,
    });

    return {
      id: agent.id,
      slug: agent.slug,
      identifier: agent.identifier,
      displayName: agent.displayName,
      status: agent.status,
      createdAt: agent.createdAt,
    };
  }

  @Get()
  @ApiOperation({
    summary: 'List agents',
    description:
      'Cursor-paginated, newest first. Optional `status` filter. See src/common/pagination/cursor-pagination.ts for the pagination convention.',
  })
  @ApiQuery({
    name: 'status',
    required: false,
    enum: ['PENDING_ENROLLMENT', 'ACTIVE', 'REVOKED', 'KILLED'],
  })
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
  @ApiResponse({ status: 200, type: AgentListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async listAgents(
    @CurrentAuth() auth: AuthContext,
    @Query('status')
    status?: 'PENDING_ENROLLMENT' | 'ACTIVE' | 'REVOKED' | 'KILLED',
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<AgentListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const page = await this.agentsService.listAgents(tenantClient, {
      status,
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
    });
    return {
      items: page.items.map((agent) => ({
        id: agent.id,
        slug: agent.slug,
        identifier: agent.identifier,
        displayName: agent.displayName,
        status: agent.status,
        createdAt: agent.createdAt,
      })),
      nextCursor: page.nextCursor,
    };
  }

  @Post(':id/enrollment-tokens')
  @ApiOperation({
    summary: 'Issue a one-time enrollment token for an agent',
    description:
      'The raw token is returned exactly once and is never retrievable again. Give it to the agent process out-of-band so it can complete `POST /agents/enroll`.',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  @ApiResponse({ status: 201, type: CreateEnrollmentTokenResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Agent not found.',
  })
  @ApiResponse({
    status: 409,
    type: ErrorResponseDto,
    description: 'Agent is REVOKED or KILLED and cannot be re-enrolled.',
  })
  async createEnrollmentToken(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
  ) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    const { rawToken, expiresAt } = await mapAgentNotFound(() =>
      this.agentsService.createEnrollmentToken(
        tenantClient,
        agentId,
        auth.tenant.slug,
        auth.user.id,
      ),
    );

    // The ONLY response that ever carries the raw token — never persisted,
    // never retrievable again (see AgentEnrollmentToken's doc comment).
    return { token: rawToken, expiresAt };
  }

  @Post(':id/revoke')
  @ApiOperation({
    summary: 'Revoke an agent',
    description:
      'Revokes the agent (its certificates stop being accepted by `AgentMtlsGuard`). Idempotent status response.',
  })
  @ApiParam({ name: 'id', description: 'Agent ID', format: 'uuid' })
  @ApiBody({ type: RevokeAgentRequestDto })
  @ApiResponse({ status: 201, type: RevokeStatusResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Agent not found.',
  })
  async revokeAgent(
    @CurrentAuth() auth: AuthContext,
    @Param('id') agentId: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(RevokeAgentRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    await mapAgentNotFound(() =>
      this.agentsService.revokeAgent(
        tenantClient,
        auth.tenant.id,
        agentId,
        input.reason,
        auth.user.id,
      ),
    );

    return { status: 'REVOKED' };
  }
}
