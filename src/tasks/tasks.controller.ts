import {
  BadRequestException,
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
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import { RevokeStatusResponseDto } from '../agents/agents.dto';
import { TaskNotFoundError } from './tasks.errors';
import { TasksService } from './tasks.service';
import {
  CreateTaskRequestSchema,
  RevokeTaskRequestSchema,
} from './tasks.validation';
import {
  CreateTaskRequestDto,
  CreateTaskResponseDto,
  RevokeTaskRequestDto,
} from './tasks.dto';

/**
 * Human-facing task management: creating a *root* task (assigning an
 * agent its first, narrowly-scoped grant of authority — Section 18) and
 * revoking one. Not explicitly named as an endpoint by the design spec
 * (which only describes the agent-facing `/agent/v1/tasks/:id/delegate`
 * surface) — but `Task.requesterId` is a required human `UserProfile` FK,
 * and every delegation chain has to start somewhere: a *root* task has no
 * parent to delegate from, so a human must be the one to create it. Gated
 * by the same `SECURITY_ADMIN`/`TENANT_OWNER` convention
 * `AgentsController` uses (tasking an agent is exactly as security-
 * relevant as creating one), plus `AI_GOVERNANCE_MANAGER` — closer to that
 * role's own remit than pure security administration.
 *
 * Revocation is deliberately task-level only this phase (no dedicated
 * kill-switch system yet — Section 32, a later phase) but is what the
 * revocation-cascade invariant (Section 20) is built on: revoking a task
 * here immediately invalidates every descendant's authorization via
 * `AuthorizationService`'s real-time ancestor walk, with no cascade write
 * to any descendant.
 */
@ApiTags('tasks')
@ApiBearerAuth('jwt')
@Controller('tasks')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('SECURITY_ADMIN', 'TENANT_OWNER', 'AI_GOVERNANCE_MANAGER')
export class TasksController {
  constructor(
    private readonly tasksService: TasksService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Post()
  @ApiOperation({
    summary: 'Create a root task',
    description:
      'Assigns an agent a narrowly-scoped grant of authority. A root task has no parent — every delegation chain starts here (see `POST /agent/v1/tasks/:id/delegate`, out of scope for this human-facing doc). Requires SECURITY_ADMIN, TENANT_OWNER, or AI_GOVERNANCE_MANAGER.',
  })
  @ApiBody({ type: CreateTaskRequestDto })
  @ApiResponse({ status: 201, type: CreateTaskResponseDto })
  @ApiResponse({
    status: 400,
    type: ErrorResponseDto,
    description:
      'Invalid body, or assignedAgentId does not resolve to an agent in this tenant.',
  })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async createTask(@CurrentAuth() auth: AuthContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(CreateTaskRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    const assignedAgent = await tenantClient.agent.findUnique({
      where: { id: input.assignedAgentId },
    });
    if (!assignedAgent) {
      throw new BadRequestException(
        `assignedAgentId "${input.assignedAgentId}" does not resolve to an agent in this tenant`,
      );
    }

    const task = await this.tasksService.createTask(
      tenantClient,
      auth.tenant.id,
      {
        name: input.name,
        description: input.description ?? null,
        requesterId: auth.user.id,
        assignedAgentId: input.assignedAgentId,
        allowedToolActions: input.allowedToolActions,
        allowedResourceSelectors: input.allowedResourceSelectors,
        forbiddenActions: input.forbiddenActions,
        startsAt: input.startsAt,
        expiresAt: input.expiresAt,
        maxExecutions: input.maxExecutions,
        riskCeiling: input.riskCeiling,
      },
    );

    return {
      id: task.id,
      status: task.status,
      assignedAgentId: task.assignedAgentId,
      expiresAt: task.expiresAt,
      createdAt: task.startsAt,
    };
  }

  @Post(':id/revoke')
  @ApiOperation({
    summary: 'Revoke a task',
    description:
      "Immediately invalidates this task and every descendant (delegated) task's authorization, enforced by AuthorizationService walking the live ancestor chain on every check — not by a cascading write to descendants.",
  })
  @ApiParam({ name: 'id', description: 'Task ID', format: 'uuid' })
  @ApiBody({ type: RevokeTaskRequestDto })
  @ApiResponse({ status: 201, type: RevokeStatusResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'Task not found.',
  })
  async revokeTask(
    @CurrentAuth() auth: AuthContext,
    @Param('id') taskId: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(RevokeTaskRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    try {
      await this.tasksService.revokeTask(
        tenantClient,
        auth.tenant.id,
        taskId,
        input.reason,
        auth.user.id,
      );
    } catch (error) {
      if (error instanceof TaskNotFoundError) {
        throw new NotFoundException(error.message);
      }
      throw error;
    }

    return { status: 'REVOKED' };
  }
}
