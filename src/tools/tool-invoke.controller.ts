import { randomUUID } from 'node:crypto';
import {
  Body,
  Controller,
  ConflictException,
  ForbiddenException,
  HttpCode,
  NotFoundException,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { FastifyReply } from 'fastify';
import type { AppConfig } from '../config/env.validation';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { AuthorizationService } from '../authorization/authorization.service';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ApprovalRequestService } from '../approvals/approval-request.service';
import { GrantService } from '../approvals/grant.service';
import { TemporalClientService } from '../temporal/temporal-client.service';
import { ApprovalWorkflow } from '../temporal/workflows/approval.workflow';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  DlpBlockedError,
  ToolActionNotFoundError,
  ToolDisabledError,
  ToolNotFoundError,
} from './credential-broker.errors';
import { CredentialBrokerService } from './credential-broker.service';
import { ToolInvokeRequestSchema } from './tool-invoke.validation';

/**
 * `POST /agent/v1/tools/invoke` — mTLS-gated (Phase 7b), extended by
 * Phase 8 to give `REQUIRE_APPROVAL` a real fulfillment path (see
 * docs/approvals.md; docs/tool-gateway.md covers the rest of this
 * controller's Phase 7b shape, unchanged).
 *
 * Two request shapes now share this one endpoint:
 *
 *   - **No `grantToken`** (the normal first attempt): calls the EXISTING,
 *     unchanged `AuthorizationService.authorize(...)` pipeline exactly as
 *     Phase 7b did.
 *       - `DENY` -> 403, no tool call ever attempted.
 *       - `REQUIRE_APPROVAL` -> creates an `ApprovalRequest`, starts
 *         `ApprovalWorkflow`, responds 202
 *         `{ status: 'PENDING', reason, riskScore, approvalId }` — no
 *         tool call is ever attempted (Section 80's "pending action cannot
 *         execute before approval" invariant; `status: 'PENDING'` keeps
 *         Phase 7b's own response shape intact for existing callers,
 *         `approvalId` is Phase 8's addition for the poll/retry flow).
 *       - `ALLOW` -> `CredentialBrokerService.invoke(...)`, unchanged.
 *   - **`grantToken` present** (an agent's retry after
 *     `GET /agent/v1/approvals/:id` reported `APPROVED`): skips
 *     `AuthorizationService.authorize` entirely — that gate was already
 *     satisfied once, at approval time (`GrantService.reevaluateAndIssueGrant`,
 *     inside the workflow's own Activity) — and instead validates the
 *     grant itself (`GrantService.validateAndConsumeGrant`: signature,
 *     expiry, single-use, and Section 80's parameter-binding invariant —
 *     `parameterHash` recomputed from *this exact request* must match). A
 *     valid, matching grant proceeds straight to
 *     `CredentialBrokerService.invoke` exactly like the `ALLOW` path
 *     above, and is marked consumed. An invalid/expired/consumed/
 *     mismatched grant -> 403, no tool call ever attempted.
 *
 * Never duplicates or forks `AuthorizationService`'s own pipeline, and
 * never calls it at all on the `grantToken` path.
 */
@Controller('agent/v1')
export class ToolInvokeController {
  constructor(
    private readonly authorizationService: AuthorizationService,
    private readonly credentialBroker: CredentialBrokerService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly approvalRequestService: ApprovalRequestService,
    private readonly grantService: GrantService,
    private readonly temporalClient: TemporalClientService,
    private readonly configService: ConfigService<AppConfig, true>,
    private readonly auditService: AuditService,
  ) {}

  @Post('tools/invoke')
  @UseGuards(AgentMtlsGuard)
  @HttpCode(200)
  async invoke(
    @CurrentAgent() agent: AgentContext,
    @Body() body: unknown,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const input = parseBodyOrThrow(ToolInvokeRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      agent.tenant.id,
    );

    if (input.grantToken) {
      const validation = await this.grantService.validateAndConsumeGrant(
        tenantClient,
        {
          tenantId: agent.tenant.id,
          agentId: agent.agent.id,
          taskId: input.taskId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
          params: input.params,
          grantToken: input.grantToken,
        },
      );
      if (!validation.valid) {
        throw new ForbiddenException({
          decision: 'DENY',
          reason: validation.reason,
        });
      }
      return this.invokeViaBroker(tenantClient, agent, input);
    }

    const decision = await this.authorizationService.authorize(
      tenantClient,
      agent.tenant.id,
      agent.agent.id,
      {
        taskId: input.taskId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
      },
    );

    if (decision.decision === 'DENY') {
      // Unlike POST /agent/v1/authorize (which always answers 200/201 —
      // see AuthorizeController's own doc comment), this endpoint's DENY
      // maps to a real 403: the design spec asks for it explicitly, and
      // there is no equivalent "learn the shape of the model from the
      // status code" concern here (this endpoint doesn't expose a
      // separate authorize-only surface a caller could probe).
      throw new ForbiddenException({
        decision: 'DENY',
        reason: decision.reason,
      });
    }
    if (decision.decision === 'REQUIRE_APPROVAL') {
      const approvalId = await this.startApproval(tenantClient, agent, input, {
        riskScore: decision.riskScore,
        policyVersionId: decision.policyVersionId,
        deterministicRiskScore: decision.deterministicRiskScore,
        aiAdvisoryScore: decision.aiAdvisoryScore,
        riskReasonCodes: decision.riskReasonCodes,
        riskCeiling: decision.riskCeiling,
        requiredReason: decision.reason,
      });
      reply.status(202);
      return {
        status: 'PENDING',
        reason: decision.reason,
        riskScore: decision.riskScore,
        approvalId,
      };
    }

    return this.invokeViaBroker(tenantClient, agent, input);
  }

  private async invokeViaBroker(
    tenantClient: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    agent: AgentContext,
    input: {
      taskId: string;
      toolId: string;
      actionId: string;
      resource: string;
      params: unknown;
    },
  ) {
    try {
      return await this.credentialBroker.invoke(tenantClient, {
        tenantId: agent.tenant.id,
        taskId: input.taskId,
        agentId: agent.agent.id,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        params: input.params,
      });
    } catch (error) {
      if (error instanceof ToolNotFoundError) {
        throw new NotFoundException(error.message);
      }
      if (error instanceof ToolActionNotFoundError) {
        throw new NotFoundException(error.message);
      }
      if (error instanceof ToolDisabledError) {
        throw new ConflictException(error.message);
      }
      if (error instanceof DlpBlockedError) {
        // Phase 10b: a severe DLP finding on outbound params blocked the
        // call before any tool contact — same 403/DENY shape as an
        // AuthorizationService DENY (see that branch above), generic
        // reason (never echoes the sensitive value or finding type back to
        // the caller — see DlpBlockedError's own doc comment).
        throw new ForbiddenException({
          decision: 'DENY',
          reason: 'dlp_policy_violation',
        });
      }
      throw error;
    }
  }

  /**
   * Creates the `ApprovalRequest` row and starts its 1:1 `ApprovalWorkflow`
   * — Section 80's invariant that no tool call is ever attempted on this
   * path holds structurally: this method never calls
   * `CredentialBrokerService` at all. Returns the new `ApprovalRequest.id`
   * (`approvalId` in the response body).
   */
  private async startApproval(
    tenantClient: Awaited<ReturnType<TenantDatabaseManager['getClient']>>,
    agent: AgentContext,
    input: {
      taskId: string;
      toolId: string;
      actionId: string;
      resource: string;
      params: unknown;
    },
    decision: {
      riskScore: number;
      policyVersionId: string | null;
      deterministicRiskScore: number;
      aiAdvisoryScore: number | null;
      riskReasonCodes: string[];
      riskCeiling: number;
      requiredReason: string;
    },
  ): Promise<string> {
    const requestTtlMs = this.configService.get('APPROVAL_REQUEST_TTL_MS', {
      infer: true,
    });
    const expiresAt = new Date(Date.now() + requestTtlMs);
    const temporalWorkflowId = `approval-${randomUUID()}`;

    const approvalRequest = await this.approvalRequestService.create(
      tenantClient,
      {
        taskId: input.taskId,
        agentId: agent.agent.id,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        params: input.params,
        riskScore: decision.riskScore,
        // Release 2026-11-11 (brief §3.4): persist the breakdown alongside
        // the total so the approver is reviewing the actual factors.
        deterministicRiskScore: decision.deterministicRiskScore,
        aiAdvisoryScore: decision.aiAdvisoryScore,
        riskReasonCodes: decision.riskReasonCodes,
        taskRiskCeiling: decision.riskCeiling,
        requiredReason: decision.requiredReason,
        policyVersionId: decision.policyVersionId,
        expiresAt,
        temporalWorkflowId,
      },
    );

    await this.temporalClient.workflow.start(ApprovalWorkflow, {
      workflowId: temporalWorkflowId,
      taskQueue: this.temporalClient.taskQueue,
      args: [
        {
          tenantId: agent.tenant.id,
          approvalRequestId: approvalRequest.id,
          expiresAtEpochMs: expiresAt.getTime(),
        },
      ],
    });

    await this.auditService.recordSafely(tenantClient, agent.tenant.id, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_REQUESTED,
      actor: { type: 'agent', id: agent.agent.id },
      data: {
        approvalRequestId: approvalRequest.id,
        taskId: input.taskId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        riskScore: decision.riskScore,
        // Release 2026-11-11 (brief §3.4): persist the breakdown alongside
        // the total so the approver is reviewing the actual factors.
        deterministicRiskScore: decision.deterministicRiskScore,
        aiAdvisoryScore: decision.aiAdvisoryScore,
        riskReasonCodes: decision.riskReasonCodes,
        taskRiskCeiling: decision.riskCeiling,
        requiredReason: decision.requiredReason,
        policyVersionId: decision.policyVersionId,
        expiresAt,
      },
    });

    return approvalRequest.id;
  }
}
