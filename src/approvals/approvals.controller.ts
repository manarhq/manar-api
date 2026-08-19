import {
  Body,
  ConflictException,
  Controller,
  Get,
  GatewayTimeoutException,
  Logger,
  NotFoundException,
  Param,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { AppConfig } from '../config/env.validation';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TemporalClientService } from '../temporal/temporal-client.service';
import { decideSignal } from '../temporal/workflows/approval.workflow';
import type { ApprovalWorkflow } from '../temporal/workflows/approval.workflow';
import type { ApprovalWorkflowResult } from '../temporal/workflows/approval-workflow.types';
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
 * design spec names: `APPROVER`/`SECURITY_ADMIN`/`TENANT_OWNER`. Signals
 * the already-running `ApprovalWorkflow` with the human's raw decision —
 * it never itself writes `ApprovalDecision`, flips
 * `ApprovalRequest.status`, or issues an `AuthorizationGrant`; all of that
 * still happens inside the workflow's own Activity
 * (`GrantService.finalizeDecision`, via `src/worker.main.ts`'s separate
 * process).
 *
 * **Security cleanup 1 (Phase 14)**: this handler used to return
 * immediately after the signal was *sent*, before the workflow had
 * actually processed it — `ApprovalRequest.status` at that point was
 * necessarily still `"PENDING"` (read before the signal), and `decision`
 * simply echoed back whatever the caller submitted, regardless of whether
 * that decision was the one that actually took effect. Phase 11b Part 2
 * found the resulting race directly: two genuinely concurrent `decide`
 * calls for the same request (a UI double-click, or two different
 * approvers) both passed the `status === 'PENDING'` check, both
 * successfully signaled the workflow, and both got back **201** — even
 * though `ApprovalWorkflow`'s `decide` signal handler is "first signal
 * wins" (see `approval.workflow.ts`), so at most one of those two
 * decisions was ever actually recorded. Not a double-execution bug
 * (Temporal processes signals for one workflow execution strictly
 * sequentially, and the workflow itself only ever acts on the first one),
 * but a real response-accuracy gap: the loser's HTTP response claimed
 * success and echoed a decision that was silently discarded.
 *
 * The fix applied here is to make the *response* correct, not to prevent
 * the second signal from being sent (there is no way to distinguish "two
 * different approvers racing" from "a legitimate retry after a dropped
 * response" at signal-send time, and the workflow's own first-signal-wins
 * handler already ensures at most one decision is ever recorded — the bug
 * was purely in what the HTTP layer reported afterward). Two designs were
 * considered:
 *
 *   - **Phase 12a's `Idempotency-Key` interceptor** (`IdempotencyInterceptor`,
 *     already applied to `POST /agents`, policy publish, kill-switch
 *     activation, webhook registration): rejected for this endpoint. That
 *     interceptor dedupes *retries of the identical request*, keyed by a
 *     caller-supplied header — it only helps when both concurrent callers
 *     send the same key, which nothing about this scenario guarantees
 *     (two different approvers race with no shared key by construction;
 *     even a UI double-click can't be relied on to attach one). It would
 *     leave the exact race Phase 11b found completely open whenever the
 *     two requests don't share a key, which is the common case here — the
 *     wrong tool for a "two genuinely different concurrent requests" race,
 *     as opposed to the "one request retried" problem it's designed for.
 *   - **Synchronously await the workflow's actual resolved outcome**
 *     (`WorkflowHandle.result()`) before responding — what this handler
 *     now does. Every concurrent caller signals the same workflow
 *     execution, then all of them await the *same* `result()` promise;
 *     Temporal resolves it once, to the one outcome the workflow's
 *     first-signal-wins handler actually acted on. Every caller's HTTP
 *     response now reports that one true outcome — the "loser" of the
 *     race gets back the decision that actually won, not their own
 *     discarded one, which is the accurate answer to "what happened to
 *     this approval request." Bounded by
 *     `APPROVAL_DECIDE_RESULT_TIMEOUT_MS` so a stalled worker still fails
 *     the request rather than hanging the HTTP connection indefinitely.
 */
@ApiTags('approvals')
@ApiBearerAuth('jwt')
@Controller('approvals')
@UseGuards(JwtAuthGuard, RolesGuard)
@RequireRole('APPROVER', 'SECURITY_ADMIN', 'TENANT_OWNER')
export class ApprovalsController {
  private readonly logger = new Logger(ApprovalsController.name);
  private readonly decideResultTimeoutMs: number;

  constructor(
    private readonly approvalRequestService: ApprovalRequestService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly temporalClient: TemporalClientService,
    configService: ConfigService<AppConfig, true>,
  ) {
    this.decideResultTimeoutMs = configService.get(
      'APPROVAL_DECIDE_RESULT_TIMEOUT_MS',
      { infer: true },
    );
  }

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
      "Signals the already-running ApprovalWorkflow with the decision, then synchronously awaits the workflow's actual resolved outcome (Phase 14 security cleanup — see this handler's doc comment for why) before responding. The returned `status`/`decision` are the real, final outcome — for two genuinely concurrent decide calls on the same request, both responses report the one decision the workflow's first-signal-wins handler actually acted on, never a discarded one. Requires APPROVER, SECURITY_ADMIN, or TENANT_OWNER.",
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
  @ApiResponse({
    status: 504,
    type: ErrorResponseDto,
    description:
      'The signal was sent but the workflow did not resolve to a final outcome within APPROVAL_DECIDE_RESULT_TIMEOUT_MS.',
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

    const result = await this.awaitWorkflowResult(
      approvalRequest.temporalWorkflowId,
      id,
    );

    return {
      id: approvalRequest.id,
      status: result.outcome,
      decision:
        result.outcome === 'APPROVED'
          ? 'APPROVE'
          : result.outcome === 'DENIED'
            ? 'DENY'
            : undefined,
    };
  }

  /**
   * Awaits `ApprovalWorkflow`'s actual terminal result for the workflow
   * this `decide` call just signaled — see the class doc comment's
   * "Security cleanup 1" section for why this replaced the old
   * "return immediately after signaling" behavior. Every concurrent
   * caller for the same `ApprovalRequest` signals the identical workflow
   * execution and then awaits the identical `result()` promise, so they
   * all observe the one true outcome, never their own possibly-discarded
   * submission.
   *
   * Bounded by `APPROVAL_DECIDE_RESULT_TIMEOUT_MS`: a stalled/unreachable
   * worker process must fail this request with a clear `504`, never hang
   * the HTTP connection indefinitely and never fabricate a "looks
   * successful" response for an outcome that hasn't actually happened yet
   * (Section 80's "never fail open" posture applies to response accuracy
   * here just as much as to authorization decisions).
   */
  private async awaitWorkflowResult(
    temporalWorkflowId: string,
    approvalRequestId: string,
  ): Promise<ApprovalWorkflowResult> {
    const handle =
      this.temporalClient.workflow.getHandle<typeof ApprovalWorkflow>(
        temporalWorkflowId,
      );

    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(
          new GatewayTimeoutException(
            `ApprovalRequest "${approvalRequestId}" was signaled but its workflow did not resolve to a final outcome within ${this.decideResultTimeoutMs}ms`,
          ),
        );
      }, this.decideResultTimeoutMs);
    });

    try {
      return await Promise.race([handle.result(), timeout]);
    } catch (error) {
      if (error instanceof GatewayTimeoutException) throw error;
      this.logger.error(
        `ApprovalWorkflow "${temporalWorkflowId}" for ApprovalRequest "${approvalRequestId}" failed while awaiting its result after a successful signal: ${error instanceof Error ? error.message : String(error)}`,
        error instanceof Error ? error.stack : undefined,
      );
      throw new ConflictException(
        `ApprovalRequest "${approvalRequestId}" was signaled but its workflow ended in an unexpected error`,
      );
    } finally {
      clearTimeout(timer);
    }
  }
}
