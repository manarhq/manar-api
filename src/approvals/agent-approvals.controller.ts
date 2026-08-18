import {
  Controller,
  Get,
  NotFoundException,
  Param,
  UseGuards,
} from '@nestjs/common';
import { CurrentAgent } from '../agent-mtls/agent-context';
import type { AgentContext } from '../agent-mtls/agent-context';
import { AgentMtlsGuard } from '../agent-mtls/agent-mtls.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { ApprovalRequestNotFoundError } from './approvals.errors';
import { ApprovalRequestService } from './approval-request.service';
import { GrantService } from './grant.service';

/**
 * `GET /agent/v1/approvals/:id` — mTLS-guarded, the endpoint an agent
 * polls after a `POST /agent/v1/tools/invoke` call comes back
 * `PENDING_APPROVAL` (Section 27/28/31 — see docs/approvals.md). Reads
 * `ApprovalRequest`/`AuthorizationGrant` state directly; it never queries
 * the Temporal workflow itself (no Temporal query handler exists — the
 * workflow's own Activities are the only thing that ever writes these
 * rows, and this endpoint only ever reads them back).
 *
 * **Must only return a grant to the agent this request was actually
 * assigned to** — `approvalRequest.agentId` is checked against the
 * mTLS-authenticated caller before anything else is returned, and a
 * mismatch answers 404 (never 403 — the same "don't confirm this
 * approval request even exists to an agent it wasn't assigned to" posture
 * `AgentMtlsGuard`'s own "unknown agent" responses already take), so a
 * grant can never leak across agents even if one somehow learned another's
 * `ApprovalRequest.id`.
 */
@Controller('agent/v1')
export class AgentApprovalsController {
  constructor(
    private readonly approvalRequestService: ApprovalRequestService,
    private readonly grantService: GrantService,
    private readonly tenantDatabaseManager: TenantDatabaseManager,
  ) {}

  @Get('approvals/:id')
  @UseGuards(AgentMtlsGuard)
  async get(@CurrentAgent() agent: AgentContext, @Param('id') id: string) {
    const tenantClient = await this.tenantDatabaseManager.getClient(
      agent.tenant.id,
    );

    let approvalRequest;
    try {
      approvalRequest = await this.approvalRequestService.getOrThrow(
        tenantClient,
        id,
      );
    } catch (error) {
      if (error instanceof ApprovalRequestNotFoundError) {
        throw new NotFoundException(`ApprovalRequest "${id}" was not found`);
      }
      throw error;
    }

    if (approvalRequest.agentId !== agent.agent.id) {
      // See class doc comment: never confirm this ApprovalRequest exists
      // at all to an agent it wasn't assigned to.
      throw new NotFoundException(`ApprovalRequest "${id}" was not found`);
    }

    const base = {
      id: approvalRequest.id,
      status: approvalRequest.status,
      taskId: approvalRequest.taskId,
      toolId: approvalRequest.toolId,
      actionId: approvalRequest.actionId,
      resource: approvalRequest.resource,
      riskScore: approvalRequest.riskScore,
      requestedAt: approvalRequest.requestedAt,
      expiresAt: approvalRequest.expiresAt,
    };

    const grant = approvalRequest.grant;
    if (
      approvalRequest.status !== 'APPROVED' ||
      !grant ||
      grant.consumedAt ||
      grant.revokedAt ||
      grant.expiresAt.getTime() <= Date.now()
    ) {
      // APPROVED-but-unusable (already consumed/expired/revoked) still
      // reports the real status — it just never hands out a token that
      // can't work anyway.
      return base;
    }

    const grantToken = await this.grantService.signGrantTokenFor(
      agent.tenant.id,
      grant,
    );

    return { ...base, grantToken, grantExpiresAt: grant.expiresAt };
  }
}
