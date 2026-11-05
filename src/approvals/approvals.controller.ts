import { isWorkspacePaused } from '../pause/pause-state';
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  ForbiddenException,
  GatewayTimeoutException,
  Header,
  HttpCode,
  Logger,
  NotFoundException,
  Param,
  UnauthorizedException,
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
import {
  ApprovalRequestNotFoundError,
  PAUSED_CONFLICT_MESSAGE,
  approvalConflict,
  notPendingConflict,
} from './approvals.errors';
import {
  APPROVER_ROLES,
  ApproverDirectory,
  isApproverRole,
  isOperatorRole,
} from './approver-directory';
import {
  STEP_UP_MAX_AGE_SECONDS,
  decisionRights,
  freshSignIn,
  refusalMessage,
  sensitiveReason,
  type DecisionRights,
} from './decision-rights';
import { ApprovalRevokeService } from './approval-revoke.service';
import {
  listApprovalHistory,
  type ApprovalHistoryStatus,
} from './approval-history';
import { HandoverStore } from '../tools/handover.store';
import { failClosed } from '../common/fail-closed/fail-closed';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { ApprovalRequestService } from './approval-request.service';
import { createAllowGrant } from './allow-grants';
import { buildRuleDraft } from './rule-draft';
import { redactForStorage } from '../contract/redact';
import {
  DecideApprovalRequestSchema,
  RevokeApprovalSchema,
} from './approvals.validation';
import {
  ApprovalRequestListResponseDto,
  DecideApprovalRequestDto,
  DecideApprovalResponseDto,
  ApprovalRequestDetailDto,
  ApprovalHistoryResponseDto,
  RevokeApprovalRequestDto,
  RevokeApprovalResponseDto,
} from './approvals.dto';

const HISTORY_STATUSES = [
  'PENDING',
  'APPROVED',
  'DENIED',
  'EXPIRED',
  'REVOKED',
] as const;

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
// Every member may open Approvals (founder decision, 3 Nov 2026): approvers see and decide
// everything; anyone else sees, and may decide, only the requests of agents they created (unless
// the workspace is "admins only"). Checked per request below.
export class ApprovalsController {
  private readonly logger = new Logger(ApprovalsController.name);
  private readonly decideResultTimeoutMs: number;

  constructor(
    private readonly approvalRequestService: ApprovalRequestService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly temporalClient: TemporalClientService,
    configService: ConfigService<AppConfig, true>,
    private readonly handoverStore: HandoverStore,
    private readonly auditService: AuditService,
    private readonly approvers: ApproverDirectory,
    private readonly revokeService: ApprovalRevokeService,
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
    enum: ['PENDING', 'APPROVED', 'DENIED', 'EXPIRED', 'REVOKED'],
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
    @Query('status')
    status?: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'REVOKED',
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<ApprovalRequestListResponseDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const admin = isApproverRole(auth.roles);
    // Not an approver and no role that operates agents (demoted, or never had one): nothing.
    if (!admin && !isOperatorRole(auth.roles))
      return { items: [], nextCursor: null };
    const page = await this.approvalRequestService.listApprovalRequests(
      tenantClient,
      {
        status,
        limit: parseLimit(limit),
        cursor: parseCursor(cursor),
        ...(admin ? {} : { agentCreatedBy: auth.user.id }),
      },
    );
    const ws = await this.approvers.workspace(auth.tenant.id);
    const names = await this.actionNames(
      tenantClient,
      page.items.map((r) => r.actionId),
    );
    const rights = page.items.map((r) =>
      this.rightsFor(auth, ws, r, r.agent.createdBy, names.get(r.actionId)),
    );
    return {
      items: page.items.map((request, i) => ({
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
        agentName: request.agent.displayName,
        ownerName: request.agent.creator.displayName,
        allowedDecisions:
          request.status === 'PENDING' ? agentChoices(rights[i]!) : [],
        needs: rights[i]!.needs,
        why: rights[i]!.why,
        stepUpNeeded: rights[i]!.stepUp && !freshSignIn(auth.authTime),
      })),
      nextCursor: page.nextCursor,
    };
  }

  @Get(':id')
  @ApiOperation({
    summary: 'The exact action under review (release 2026-11-11)',
    description:
      'The immutable, safely redacted snapshot a reviewer needs before approving: the invocation parameters, the parameterDigest an issued grant is bound to, the risk breakdown with deterministic factors and AI signals SEPARATELY attributed, why approval was required, the policy version, expiry, and what the action actually does. Redaction is key-name based, not content-based DLP -- redactedKeyPaths names every withheld value so a partial object is never read as a complete one. Reachable only on the human JWT surface; an agent uses the separate mTLS listener.',
  })
  @ApiParam({ name: 'id', description: 'ApprovalRequest ID', format: 'uuid' })
  @ApiResponse({ status: 200, type: ApprovalRequestDetailDto })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({
    status: 404,
    type: ErrorResponseDto,
    description: 'No such approval request in this tenant.',
  })
  async getOne(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<ApprovalRequestDetailDto> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    try {
      const detail = await this.approvalRequestService.getDetailOrThrow(
        tenantClient,
        id,
      );
      const access = await this.access(auth, tenantClient, {
        ...detail,
        actionName: detail.expectedEffect?.actionName,
      });
      if (!access.visible) throw new ApprovalRequestNotFoundError(id);
      const revoker = detail.revokedBy
        ? await tenantClient.userProfile.findUnique({
            where: { id: detail.revokedBy },
            select: { displayName: true },
          })
        : null;
      return {
        id: detail.id,
        taskId: detail.taskId,
        agentId: detail.agentId,
        toolId: detail.toolId,
        actionId: detail.actionId,
        resource: detail.resource,
        status: detail.status,
        requestedAt: detail.requestedAt,
        expiresAt: detail.expiresAt,
        params: detail.parameters.params,
        redactedKeyPaths: detail.parameters.redactedKeyPaths,
        parametersTruncated: detail.parameters.truncated,
        parameterDigest: detail.parameterDigest,
        riskScore: detail.riskScore,
        deterministicRiskScore: detail.deterministicRiskScore,
        aiAdvisoryScore: detail.aiAdvisoryScore,
        taskRiskCeiling: detail.taskRiskCeiling,
        requiredReason: detail.requiredReason,
        deterministicReasonCodes: detail.deterministicReasonCodes,
        aiAdvisoryReasonCodes: detail.aiAdvisoryReasonCodes,
        policyVersionId: detail.policyVersionId,
        expectedEffect: detail.expectedEffect as Record<string, unknown> | null,
        decisions: detail.decisions as unknown as Record<string, unknown>[],
        grantIssued: detail.grantIssued,
        grantConsumedAt: detail.grantConsumedAt,
        allowedDecisions:
          detail.status === 'PENDING' ? agentChoices(access.rights) : [],
        needs: access.rights.needs,
        why: access.rights.why,
        stepUpNeeded: access.rights.stepUp && !freshSignIn(auth.authTime),
        selfConfirmedAt: detail.selfConfirmedAt,
        canRevoke: detail.status === 'APPROVED' && access.rights.canRevoke,
        releasedAt: detail.releasedAt,
        revokedAt: detail.revokedAt,
        revokedByName: detail.revokedBy
          ? (revoker?.displayName ?? 'A former member')
          : null,
        revokeNote: detail.revokeNote,
        usedBeforeRevoke: detail.usedBeforeRevoke,
        endReason: detail.endReason,
      };
    } catch (error) {
      if (error instanceof ApprovalRequestNotFoundError) {
        throw new NotFoundException(error.message);
      }
      throw error;
    }
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

    const access = await this.access(auth, tenantClient, approvalRequest);
    if (!access.visible)
      throw new NotFoundException('That approval was not found.');
    const choice =
      input.decision === 'DENY'
        ? 'deny'
        : input.extended
          ? 'approve_8h'
          : 'approve_once';
    if (!access.rights.choices.includes(choice))
      throw new ForbiddenException(refusalMessage(access.rights));
    // A rule is a standing approval: only an approver, and only when they may approve outright.
    // Self-approval of something sensitive (personal workspace): only right after a fresh sign-in,
    // checked here on the server; the web sends the person through sign-in and back.
    const selfConfirmed = access.rights.stepUp && choice !== 'deny';
    if (selfConfirmed && !freshSignIn(auth.authTime))
      throw new UnauthorizedException({
        statusCode: 401,
        code: 'reauth_required',
        maxAge: STEP_UP_MAX_AGE_SECONDS,
        message:
          'Confirm it is you (sign in again) to approve your own high-risk request. Nothing was changed.',
      });
    if (input.makeRule && !access.rights.choices.includes('approve_8h'))
      throw new ForbiddenException(
        'Only a workspace approver can turn an approval into a rule. Nothing was changed.',
      );

    // No approval is granted while AI is paused; a deny stays possible.
    if (input.decision !== 'DENY' && (await isWorkspacePaused(tenantClient))) {
      throw approvalConflict('paused', PAUSED_CONFLICT_MESSAGE);
    }

    if (approvalRequest.status !== 'PENDING') {
      throw notPendingConflict(approvalRequest.status);
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
      if (refreshed.status !== 'PENDING')
        throw notPendingConflict(refreshed.status);
      throw approvalConflict(
        'not_signaled',
        'Your answer could not be delivered. Nothing was changed. Try again in a moment.',
      );
    }

    const result = await this.awaitWorkflowResult(
      approvalRequest.temporalWorkflowId,
      id,
    );

    if (selfConfirmed && result.outcome === 'APPROVED') {
      await tenantClient.approvalRequest.update({
        where: { id: approvalRequest.id },
        data: { selfConfirmedAt: new Date() },
      });
      await this.auditService.recordSafely(tenantClient, auth.tenant.id, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_SELF_CONFIRMED,
        actor: { type: 'human', id: auth.user.id },
        data: {
          approvalRequestId: approvalRequest.id,
          selfApproved: true,
          sensitive: access.rights.why,
          reconfirmed: true,
          authTime: auth.authTime ?? null,
        },
      });
    }

    // "Approve for 8 hours": only after the workflow really approved (re-evaluation can still
    // deny), for this agent, tool, action and exact resource.
    let grantId: string | undefined;
    if (input.extended && result.outcome === 'APPROVED') {
      const grant = await failClosed('tenant-db', () =>
        createAllowGrant(tenantClient, {
          scope: { agentId: approvalRequest.agentId },
          target: {
            toolId: approvalRequest.toolId,
            actionId: approvalRequest.actionId,
            resource: approvalRequest.resource,
          },
          createdBy: auth.user.keycloakSubject,
          sourceId: approvalRequest.id,
        }),
      );
      grantId = grant.id;
      await this.auditService.recordSafely(tenantClient, auth.tenant.id, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_CREATED,
        actor: { type: 'human', id: auth.user.id },
        data: {
          grantId,
          approvalRequestId: approvalRequest.id,
          agentId: approvalRequest.agentId,
          toolId: approvalRequest.toolId,
          actionId: approvalRequest.actionId,
        },
      });
    }

    return {
      id: approvalRequest.id,
      status: result.outcome,
      decision:
        result.outcome === 'APPROVED'
          ? 'APPROVE'
          : result.outcome === 'DENIED'
            ? 'DENY'
            : undefined,
      ...(grantId ? { grantId } : {}),
      ...(input.makeRule && result.outcome === 'APPROVED'
        ? { ruleDraft: buildRuleDraft(approvalRequest) }
        : {}),
    };
  }

  @Get('history')
  @ApiOperation({
    summary: 'Every approval, agent and device, in every state (3 Nov 2026)',
    description:
      'Newest first, one cursor over agent and device approvals: who decided, when, through which channel, what it created (8-hour grant, site rule, block), whether the device or agent had received it, and whether it was revoked. A person who is not an approver sees only their own devices and agents. `allowedDecisions` and `canRevoke` say what the signed-in person may do.',
  })
  @ApiQuery({ name: 'status', required: false, enum: HISTORY_STATUSES })
  @ApiQuery({ name: 'limit', required: false, type: Number })
  @ApiQuery({ name: 'cursor', required: false })
  @ApiResponse({ status: 200, type: ApprovalHistoryResponseDto })
  async history(
    @CurrentAuth() auth: AuthContext,
    @Query('status') status?: string,
    @Query('limit') limit?: string,
    @Query('cursor') cursor?: string,
  ): Promise<ApprovalHistoryResponseDto> {
    if (
      status !== undefined &&
      !(HISTORY_STATUSES as readonly string[]).includes(status)
    )
      throw new BadRequestException('Unknown status filter.');
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const admin = isApproverRole(auth.roles);
    if (!admin && !isOperatorRole(auth.roles))
      return { items: [], nextCursor: null, seesAll: false };
    const ws = await this.approvers.workspace(auth.tenant.id);
    const page = await listApprovalHistory(tenantClient, {
      limit: parseLimit(limit),
      cursor: parseCursor(cursor),
      status: status as ApprovalHistoryStatus | undefined,
      viewer: {
        userId: auth.user.id,
        subject: auth.user.keycloakSubject,
        admin,
        // The owner path: a role that may operate agents and devices now.
        operator: isOperatorRole(auth.roles),
        ...ws,
      },
    });
    return { ...page, seesAll: admin };
  }

  @Get('allow-grants')
  @RequireRole(...APPROVER_ROLES)
  @ApiOperation({
    summary: 'Live permissions that skip the prompt, with where they came from',
    description:
      'Every live 8-hour grant and every "always allow this here" rule (origin: approval, offer or learning), newest first. Withdraw one with POST /approvals/allow-grants/:grantId/revoke. Approvers only.',
  })
  async listGrants(@CurrentAuth() auth: AuthContext) {
    const client = await this.tenantDatabaseManager.getClient(auth.tenant.id);
    const rows = await client.approvalAllowGrant.findMany({
      where: {
        effect: 'ALLOW',
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      include: { host: { select: { hostname: true } } },
      orderBy: { createdAt: 'desc' },
      take: 200,
    });
    return {
      items: rows.map((g) => ({
        id: g.id,
        origin: g.origin,
        hostId: g.hostId,
        hostName: g.host?.hostname ?? null,
        agentId: g.agentId,
        toolId: g.toolId,
        actionId: g.actionId,
        // The scope an always-allow covers, or the one exact resource of an 8-hour grant.
        scope: redactForStorage(g.resourcePattern ?? g.resource),
        createdAt: g.createdAt,
        expiresAt: g.expiresAt,
        useCount: g.useCount,
        lastUsedAt: g.lastUsedAt,
      })),
    };
  }

  @Post('allow-grants/:grantId/revoke')
  @HttpCode(200)
  @RequireRole(...APPROVER_ROLES)
  @ApiOperation({
    summary:
      'Withdraw an 8-hour approval, or lift a block left by a revoked-after-use approval',
    description:
      'Takes effect on the very next request: both authorize paths look grants and blocks up live, and nothing is cached on the device. Approvers only.',
  })
  @ApiParam({ name: 'grantId', format: 'uuid' })
  async revokeGrant(
    @CurrentAuth() auth: AuthContext,
    @Param('grantId') grantId: string,
  ) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    return this.revokeService.revokeGrant(
      tenantClient,
      auth.tenant.id,
      grantId,
      {
        userId: auth.user.id,
        subject: auth.user.keycloakSubject,
      },
    );
  }

  @Post(':id/revoke')
  @HttpCode(200)
  @ApiOperation({
    summary: 'Revoke an approval given by mistake',
    description:
      'Not yet received by the agent: cancelled at once; the one-use grant is revoked and the agent sees REVOKED. Already received: marked revoked after use, the admins are alerted (push and an incident) and this exact action is blocked until someone lifts the block. Either way any 8-hour grant it created is withdrawn. Approvers, or the agent\'s creator unless the workspace is "admins only".',
  })
  @ApiParam({ name: 'id', format: 'uuid' })
  @ApiBody({ type: RevokeApprovalRequestDto })
  @ApiResponse({ status: 200, type: RevokeApprovalResponseDto })
  @ApiResponse({ status: 409, type: ErrorResponseDto })
  async revoke(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
    @Body() body: unknown,
  ): Promise<RevokeApprovalResponseDto> {
    const input = parseBodyOrThrow(RevokeApprovalSchema, body ?? {});
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const row = await tenantClient.approvalRequest.findUnique({
      where: { id },
      select: { agentId: true, actionId: true, riskScore: true },
    });
    const access = row ? await this.access(auth, tenantClient, row) : null;
    if (!access?.visible)
      throw new NotFoundException('That approval was not found.');
    if (!access.rights.canRevoke)
      throw new ForbiddenException(
        'Only a workspace approver can revoke this approval. Nothing was changed.',
      );
    return this.revokeService.revokeAgent(
      tenantClient,
      auth.tenant.id,
      id,
      { userId: auth.user.id, subject: auth.user.keycloakSubject },
      input.note,
    );
  }

  /**
   * The rights of the signed-in person over one agent request (decision-rights.ts). The owner path
   * is the agent's creator who holds a role that may operate agents *now*: `Agent.createdBy` never
   * changes, so a demoted or removed creator must not keep deciding.
   */
  private rightsFor(
    auth: AuthContext,
    ws: { adminsOnly: boolean; company: boolean },
    request: { actionId: string; riskScore: number },
    createdBy: string | null | undefined,
    actionName?: string | null,
  ): DecisionRights {
    return decisionRights({
      admin: isApproverRole(auth.roles),
      owner: createdBy === auth.user.id && isOperatorRole(auth.roles),
      adminsOnly: ws.adminsOnly,
      company: ws.company,
      sensitive: sensitiveReason({
        actionId: request.actionId,
        actionName,
        riskScore: request.riskScore,
      }),
      actionId: request.actionId,
    });
  }

  /** Whether the person may see this agent's request, and what they may do with it. */
  private async access(
    auth: AuthContext,
    tenantClient: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    request: {
      agentId: string;
      actionId: string;
      riskScore: number;
      actionName?: string | null;
    },
  ): Promise<{ visible: boolean; rights: DecisionRights }> {
    const agent = await tenantClient.agent.findUnique({
      where: { id: request.agentId },
      select: { createdBy: true },
    });
    const name =
      request.actionName ??
      (await this.actionNames(tenantClient, [request.actionId])).get(
        request.actionId,
      );
    const rights = this.rightsFor(
      auth,
      await this.approvers.workspace(auth.tenant.id),
      request,
      agent?.createdBy,
      name,
    );
    const owner =
      agent?.createdBy === auth.user.id && isOperatorRole(auth.roles);
    return { visible: isApproverRole(auth.roles) || owner, rights };
  }

  /** Action names by id, for the handover check (an action id may be a uuid or the name itself). */
  private async actionNames(
    tenantClient: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    ids: string[],
  ): Promise<Map<string, string>> {
    if (ids.length === 0) return new Map();
    const rows = await tenantClient.toolAction.findMany({
      where: { id: { in: [...new Set(ids)] } },
      select: { id: true, name: true },
    });
    return new Map(rows.map((r) => [r.id, r.name]));
  }

  @Post(':id/handover')
  // A handover releases a secret (a temporary password): approvers only, whatever else changes.
  @RequireRole(...APPROVER_ROLES)
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  @ApiOperation({
    summary: 'Collect, once, what an approved action produced for its approver',
    description:
      'ADR-0011. Some actions produce a value only the approving person may see, never the agent: the temporary password of entra.user.password.reset and entra.user.create. Only the person who approved this request can collect it, exactly once; it is then deleted from OpenBao (KV v1, no versions). 404 when there is nothing to collect (not executed yet, already collected, expired after 24 h, or the action produces nothing). 503 when OpenBao is unavailable; there is no other store.',
  })
  @ApiParam({ name: 'id', description: 'ApprovalRequest ID', format: 'uuid' })
  @ApiResponse({ status: 200, description: '`{ approvalRequestId, value }`' })
  @ApiResponse({ status: 401, type: ErrorResponseDto })
  @ApiResponse({ status: 403, type: ErrorResponseDto })
  @ApiResponse({ status: 404, type: ErrorResponseDto })
  async collectHandover(
    @CurrentAuth() auth: AuthContext,
    @Param('id') id: string,
  ): Promise<{ approvalRequestId: string; value: Record<string, string> }> {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      auth.tenant.id,
    );
    const approved = await tenantClient.approvalDecision.findFirst({
      where: { approvalRequestId: id, decision: 'APPROVE' },
      select: { approverId: true },
    });
    if (!approved) throw new NotFoundException('nothing to collect');
    if (approved.approverId !== auth.user.id) {
      throw new ForbiddenException(
        'only the person who approved this request can collect its handover',
      );
    }
    // Fail closed: OpenBao is the only store; when it fails this is a 503, never a fallback.
    const value = await failClosed('openbao', () =>
      this.handoverStore.take(auth.tenant.id, id),
    );
    if (!value) throw new NotFoundException('nothing to collect');
    await this.auditService.recordSafely(tenantClient, auth.tenant.id, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_HANDOVER_COLLECTED,
      actor: { type: 'human', id: auth.user.id },
      // Which fields were handed over, never their values.
      data: { approvalRequestId: id, fields: Object.keys(value) },
    });
    return { approvalRequestId: id, value };
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
      throw approvalConflict(
        'not_signaled',
        'Your answer was sent but we could not confirm the result. Check this request again in a moment before answering again.',
      );
    } finally {
      clearTimeout(timer);
    }
  }
}

/** An agent request has no "always" (that is for a new site on a device). */
function agentChoices(rights: DecisionRights): string[] {
  return rights.choices.filter((c) => c !== 'approve_always');
}
