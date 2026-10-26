import { Body, Controller, Logger, Post, UseGuards } from '@nestjs/common';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { AuthorizeRequestSchema } from './authorize-request.validation';
import { AuthorizationService } from './authorization.service';
import { ToolInvocationService } from '../tools/tool-invocation.service';

/**
 * `POST /agent/v1/authorize` — mTLS-gated (Phase 4's `AgentMtlsGuard`), the
 * only entry point into `AuthorizationService`'s 6-step pipeline. Always
 * responds 200/201 with `{ decision: 'ALLOW' }` or `{ decision: 'DENY',
 * reason }` for a well-formed request against a real caller — a DENY is a
 * legitimate, expected answer from a policy-decision-point endpoint, not
 * an HTTP-level error, so it never maps to a 403/404 (which would leak
 * *why* through the HTTP status code alone, on top of the returned
 * `reason` — a caller should learn the reason exactly once, from the body,
 * not twice from two different signals). Malformed request bodies still
 * 400 via `parseBodyOrThrow`, same as every other validated endpoint.
 *
 * `APPROVAL_REQUIRED` opens an `ApprovalRequest` (and its workflow) exactly
 * like `tools/invoke` does and returns its `approvalId` and `expiresAt`, so a
 * caller that executes the action itself (the manar-edge Claude Code hook,
 * docs/edge.md) can poll `GET /agent/v1/approvals/:id`. `APPROVED` is then its
 * answer: no grant is redeemed, Manar executes nothing. If the request cannot
 * be opened, the verdict is returned without `approvalId` and such a caller
 * denies. Registered in `ToolInvokeModule`, which owns the approval start.
 */
@Controller('agent/v1')
export class AuthorizeController {
  private readonly logger = new Logger(AuthorizeController.name);

  constructor(
    private readonly authorizationService: AuthorizationService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly toolInvocation: ToolInvocationService,
  ) {}

  @Post('authorize')
  @UseGuards(AgentMtlsGuard)
  async authorize(@CurrentAgent() agent: AgentContext, @Body() body: unknown) {
    const input = parseBodyOrThrow(AuthorizeRequestSchema, body);
    const tenantClient = await this.tenantDatabaseManager.getClient(
      agent.tenant.id,
    );

    const decision = await this.authorizationService.authorize(
      tenantClient,
      agent.tenant.id,
      agent.agent.id,
      input,
    );
    if (decision.decision !== 'APPROVAL_REQUIRED') return decision;
    try {
      const approval = await this.toolInvocation.startApproval(
        tenantClient,
        agent,
        { ...input, params: {} },
        {
          riskScore: decision.riskScore,
          policyVersionId: decision.policyVersionId,
          deterministicRiskScore: decision.deterministicRiskScore,
          aiAdvisoryScore: null,
          advisoryUnavailable: true,
          riskReasonCodes: decision.riskReasonCodes,
          riskCeiling: decision.riskCeiling,
          requiredReason: decision.reason,
          decisionId: decision.decisionId,
        },
      );
      return {
        ...decision,
        approvalId: approval.id,
        expiresAt: approval.expiresAt,
      };
    } catch (error) {
      this.logger.warn(
        `approval request for decision ${decision.decisionId} could not be opened: ${(error as Error).message}`,
      );
      return decision;
    }
  }
}
