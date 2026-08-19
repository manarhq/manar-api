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
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { AgentNotFoundError } from './agents.errors';
import { AgentsService } from './agents.service';
import {
  CreateAgentRequestSchema,
  RevokeAgentRequestSchema,
} from './agents.validation';
import {
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
  ) {}

  @Post()
  @ApiOperation({
    summary: 'Create an agent record',
    description:
      'Creates the Agent row in `PENDING_ENROLLMENT` status. Does not itself issue an enrollment token — call `POST /agents/:id/enrollment-tokens` next. Requires SECURITY_ADMIN or TENANT_OWNER.',
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
