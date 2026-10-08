import { randomUUID } from 'node:crypto';
import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { AppConfig } from '../config/env.validation';
import type { AgentContext } from '../agent-mtls/agent-context';
import {
  AuthorizationService,
  type DecisionChannel,
} from '../authorization/authorization.service';
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
import { failClosed } from '../common/fail-closed/fail-closed';
import type { ToolInvokeRequest } from './tool-invoke.validation';
import type { ToolInvocationResult } from './tool-protocol-adapter.interface';

type TenantClient = Awaited<ReturnType<TenantDatabaseManager['getClient']>>;

export interface PendingApprovalOutcome {
  status: 'PENDING';
  reason: string;
  riskScore: number;
  approvalId: string;
}

/** What the pipeline answers when it did not throw: the tool's result (executed) or a pending approval. */
export type ToolInvocationOutcome =
  ToolInvocationResult | PendingApprovalOutcome;

export function isPendingApproval(
  outcome: ToolInvocationOutcome,
): outcome is PendingApprovalOutcome {
  return (outcome as PendingApprovalOutcome).status === 'PENDING';
}

/**
 * The one pipeline behind both agent doors to a tool: `POST
 * /agent/v1/tools/invoke` (REST) and `tools/call` on the governed MCP server
 * (ADR-0002). Moved out of `ToolInvokeController` unchanged so the two doors
 * cannot drift.
 *
 * Two request shapes:
 *
 *   - **No `grantToken`** (the normal first attempt): the existing
 *     `AuthorizationService.authorize(...)` pipeline.
 *       - `DENY` -> `ForbiddenException({ decision: 'DENY', reason })`, no
 *         tool call ever attempted.
 *       - `APPROVAL_REQUIRED` -> creates an `ApprovalRequest`, starts
 *         `ApprovalWorkflow`, returns `{ status: 'PENDING', reason,
 *         riskScore, approvalId }` — no tool call is ever attempted.
 *       - `ALLOW` -> `CredentialBrokerService.invoke(...)`.
 *   - **`grantToken` present** (the retry after `GET /agent/v1/approvals/:id`
 *     reported `APPROVED`; on the MCP door, the token of a matching approved
 *     grant the server found itself, ADR-0007): `GrantService.verifyGrant` checks the grant is
 *     for *this exact request* (signature, expiry, revocation, single use,
 *     parameter hash), then `AuthorizationService.authorizeRedemption`
 *     re-runs the full decision against current state (S6/F7) and consumes
 *     the grant only if it still allows. Anything else is a 403 DENY.
 *
 * ADR-003: every path records a `Decision` before anything executes, and the
 * broker runs under that decision's id (`ToolInvocation.decisionId`). If the
 * decision cannot be written the request is a 503 and nothing executes.
 *
 * Errors are Nest HTTP exceptions (403 DENY, 404 unknown tool/action, 409
 * disabled tool, 503 `enforcement_dependency_unavailable`) so the REST
 * controller can let them through unchanged and the MCP server can map them.
 */
@Injectable()
export class ToolInvocationService {
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

  async invoke(
    agent: AgentContext,
    input: ToolInvokeRequest,
    channel: Extract<DecisionChannel, 'REST' | 'MCP'>,
  ): Promise<ToolInvocationOutcome> {
    const tenantClient = await failClosed('tenant-db', () =>
      this.tenantDatabaseManager.getClient(agent.tenant.id),
    );

    // ADR-0007: an MCP `tools/call` cannot carry a grant token, so on the MCP
    // door the server looks for the grant a person approved for exactly this
    // agent, task, tool, action, resource and parameter hash, and redeems it
    // through the same path as a token sent over REST.
    const grantToken =
      input.grantToken ??
      (channel === 'MCP'
        ? await failClosed('grant-store', () =>
            this.grantService.findRedeemableGrantToken(tenantClient, {
              tenantId: agent.tenant.id,
              agentId: agent.agent.id,
              taskId: input.taskId,
              toolId: input.toolId,
              actionId: input.actionId,
              resource: input.resource,
              params: input.params,
            }),
          )
        : null);

    if (grantToken) {
      // S6/F7: verify the grant is for this exact request (signature,
      // expiry, revocation, single use, parameter binding), then re-run the
      // full decision against current state. Only a still-allowed decision
      // consumes the grant, in the same transaction as its `Decision` row.
      // Gate 0 finding S33: a grant-store failure is a 503, not a bare 500.
      const grantCheck = await failClosed('grant-store', () =>
        this.grantService.verifyGrant(tenantClient, {
          tenantId: agent.tenant.id,
          agentId: agent.agent.id,
          taskId: input.taskId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
          params: input.params,
          grantToken,
        }),
      );
      const redemption = await this.authorizationService.authorizeRedemption(
        tenantClient,
        agent.tenant.id,
        agent.agent.id,
        {
          taskId: input.taskId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
        },
        { channel, params: input.params },
        grantCheck,
      );
      await this.auditService.recordSafely(tenantClient, agent.tenant.id, {
        eventType:
          redemption.decision === 'ALLOW'
            ? AUDIT_EVENT_TYPES.APPROVAL_GRANT_REDEEMED
            : AUDIT_EVENT_TYPES.APPROVAL_GRANT_REJECTED,
        actor: { type: 'agent', id: agent.agent.id },
        data: {
          taskId: input.taskId,
          toolId: input.toolId,
          actionId: input.actionId,
          resource: input.resource,
          decisionId: redemption.decisionId,
          ...(grantCheck.valid ? { grantId: grantCheck.grantId } : {}),
          ...(redemption.decision === 'ALLOW'
            ? {}
            : { reason: redemption.reason }),
        },
      });
      if (redemption.decision !== 'ALLOW') {
        throw new ForbiddenException({
          decision: 'DENY',
          reason: redemption.reason,
          decisionId: redemption.decisionId,
        });
      }
      return this.invokeViaBroker(
        tenantClient,
        agent,
        input,
        redemption.decisionId,
      );
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
      { channel, params: input.params },
    );

    if (decision.decision === 'DENY') {
      throw new ForbiddenException({
        decision: 'DENY',
        reason: decision.reason,
        decisionId: decision.decisionId,
      });
    }
    if (decision.decision === 'APPROVAL_REQUIRED') {
      // ADR-0007: an MCP client repeats the call while it waits; answer with
      // the request a person is already looking at rather than a second one.
      const open =
        channel === 'MCP'
          ? await failClosed('tenant-db', () =>
              this.approvalRequestService.findPendingMatch(tenantClient, {
                taskId: input.taskId,
                agentId: agent.agent.id,
                toolId: input.toolId,
                actionId: input.actionId,
                resource: input.resource,
                params: input.params,
              }),
            )
          : null;
      const approvalId =
        open?.id ??
        (await this.startApproval(tenantClient, agent, input, {
          riskScore: decision.riskScore,
          policyVersionId: decision.policyVersionId,
          deterministicRiskScore: decision.deterministicRiskScore,
          // ADR-004: the advisory is not a decision input, so nothing is known
          // about it here. `ApprovalWorkflow` fetches it off the decision path
          // for the human approver; until then the approval records that no
          // advisory is attached rather than implying a low one.
          aiAdvisoryScore: null,
          advisoryUnavailable: true,
          riskReasonCodes: decision.riskReasonCodes,
          riskCeiling: decision.riskCeiling,
          requiredReason: decision.reason,
          decisionId: decision.decisionId,
        }));
      return {
        status: 'PENDING',
        reason: decision.reason,
        riskScore: decision.riskScore,
        approvalId,
      };
    }

    return this.invokeViaBroker(
      tenantClient,
      agent,
      input,
      decision.decisionId,
    );
  }

  private async invokeViaBroker(
    tenantClient: TenantClient,
    agent: AgentContext,
    input: ToolInvokeRequest,
    decisionId: string,
  ): Promise<ToolInvocationResult> {
    try {
      return await this.credentialBroker.invoke(tenantClient, {
        tenantId: agent.tenant.id,
        taskId: input.taskId,
        agentId: agent.agent.id,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        params: input.params,
        decisionId,
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
        // A severe DLP finding on outbound params blocked the call before
        // any tool contact. Generic reason: never echoes the sensitive value
        // or finding type back to the caller.
        throw new ForbiddenException({
          decision: 'DENY',
          reason: 'dlp_policy_violation',
        });
      }
      throw error;
    }
  }

  /**
   * Creates the `ApprovalRequest` row and starts its 1:1 `ApprovalWorkflow`.
   * Never calls `CredentialBrokerService`, so a pending action cannot
   * execute before approval.
   */
  private async startApproval(
    tenantClient: TenantClient,
    agent: AgentContext,
    input: ToolInvokeRequest,
    decision: {
      riskScore: number;
      policyVersionId: string | null;
      deterministicRiskScore: number;
      aiAdvisoryScore: number | null;
      advisoryUnavailable: boolean;
      riskReasonCodes: string[];
      riskCeiling: number;
      requiredReason: string;
      decisionId: string;
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
        deterministicRiskScore: decision.deterministicRiskScore,
        aiAdvisoryScore: decision.aiAdvisoryScore,
        advisoryUnavailable: decision.advisoryUnavailable,
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
        decisionId: decision.decisionId,
        taskId: input.taskId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        riskScore: decision.riskScore,
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
