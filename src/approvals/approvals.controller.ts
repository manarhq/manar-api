import {
  Body,
  ConflictException,
  Controller,
  Get,
  Logger,
  NotFoundException,
  Param,
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
import { TemporalClientService } from '../temporal/temporal-client.service';
import { decideSignal } from '../temporal/workflows/approval.workflow';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ErrorResponseDto } from '../common/openapi/error-response.dto';
import {
  parseCursor,
  parseLimit,
} from '../common/pagination/cursor-pagination';
import { ApprovalRequestNotFoundError } from './approvals.errors';
import { ApprovalRequestService } from './approval-request.service';
import { DecideApprovalRequestSchema } from './approvals.validation';
import {
  ApprovalRequestListResponseDto,
  DecideApprovalRequestDto,
  DecideApprovalResponseDto,
} from './approvals.dto';

/**
 * `POST /approvals/:id/decide` — Section 27/28/31's human decision surface
 * (see docs/approvals.md). JWT-guarded, gated to the three roles the
 * design spec names: `APPROVER`/`SECURITY_ADMIN`/`TENANT_OWNER`. Does
 * exactly one thing: signals the already-running `ApprovalWorkflow` with
 * the human's raw decision — it never itself writes `ApprovalDecision`,
 * flips `ApprovalRequest.status`, or issues an `AuthorizationGrant`. All of
 * that happens inside the workflow's own Activity
 * (`GrantService.finalizeDecision`, via `src/worker.main.ts`'s separate
 * process) once the signal is delivered — this handler returns as soon as
 * the signal is *sent*, not once it's been fully processed (the caller —
 * or the agent, via `GET /agent/v1/approvals/:id` — observes the eventual
 * outcome by polling, exactly as the design spec's flow describes).
 */
@ApiTags('approvals')
@ApiBearerAuth('jwt')
@Controller('approvals')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('APPROVER', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class ApprovalsController {
  private readonly logger = new Logger(ApprovalsController.name);

  constructor(
    private readonly approvalRequestService: ApprovalRequestService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly temporalClient: TemporalClientService,
  ) {}

  @Get()
  @ApiOperation({
    summary: 'List approval requests',
    description:
      'Cursor-paginated, newest first (by requestedAt). Optional `status` filter — an operator queue view is typically `?status=PENDING`.',
  })
  @ApiQuery({
    name: 'status',
    required: false,
    enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED'],
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
  @ApiResponse({ status: 200, type: ApprovalRequestListResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  async list(
    @CurrentAuth() auth: AuthContext,
    @Query('status') status?: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED',
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<ApprovalRequestListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const page = await this.approvalRequestService.listApprovalRequests(
      tenantClient,
      {
        status,
        limit: parseLimit(limit),
        cursor: parseCursor(cursor),
      },
    );
    return {
      items: page.items.map((request) => ({
        id: request.id,
        taskId: request.taskId,
        agentId: request.agentId,
        toolId: request.toolId,
        actionId: request.actionId,
        resource: request.resource,
        riskScore: request.riskScore,
        policyVersionId: request.policyVersionId,
        status: request.status,
        requestedAt: request.requestedAt,
        expiresAt: request.expiresAt,
      })),
      nextCursor: page.nextCursor,
    };
  }

  @Post(':id/decide')
  @ApiOperation({
    summary: 'Record a human decision on a pending approval request',
    description:
      'Signals the already-running ApprovalWorkflow with the decision and returns as soon as the signal is sent — not once fully processed. The eventual outcome (APPROVED/DENIED) is observed later by the agent polling `GET /agent/v1/approvals/:id`. Requires APPROVER, SECURITY_ADMIN, or TENANT_OWNER.',
  })
  @ApiParam({ name: 'id', description: 'ApprovalRequest ID', format: 'uuid' })
  @ApiBody({ type: DecideApprovalRequestDto })
  @ApiResponse({ status: 201, type: DecideApprovalResponseDto })
  @ApiResponse({ status: 400, type: ErrorResponseDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'ApprovalRequest not found.',
  })
  @ApiResponse({
    status: 409,
    type: ErrorResponseDto,
    description: 'Request is not PENDING, or could not be signaled.',
  })
  async decide(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ) {
    const input = parseBodyOrThrow(DecideApprovalRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );

    let approvalRequest;
    try {
      approvalRequest = await this.approvalRequestService.getOrThrow(
        tenantClient,
        id,
      );
    } catch (error) {
      if (error instanceof ApprovalRequestNotFoundError) {
        throw new NotFoundException(error.message);
      }
      throw error;
    }

    if (approvalRequest.status !== 'PENDING') {
      throw new ConflictException(
        `ApprovalRequest "${id}" is not PENDING (current status: "${approvalRequest.status}") — it has already been decided or has expired`,
      );
    }

    try {
      await this.temporalClient.workflow
        .getHandle(approvalRequest.temporalWorkflowId)
        .signal(decideSignal, {
          decision: input.decision,
          approverId: auth.user.id,
          reason: input.reason,
        });
    } catch (error) {
      this.logger.warn(
        `Failed to signal ApprovalWorkflow "${approvalRequest.temporalWorkflowId}" for ApprovalRequest "${id}": ${error instanceof Error ? error.message : String(error)}`,
      );
      const refreshed = await this.approvalRequestService.getOrThrow(
        tenantClient,
        id,
      );
      throw new ConflictException(
        `ApprovalRequest "${id}" could not be signaled — its workflow may have already completed (current status: "${refreshed.status}")`,
      );
    }

    return {
      id: approvalRequest.id,
      status: approvalRequest.status,
      decision: input.decision,
    };
  }
}
