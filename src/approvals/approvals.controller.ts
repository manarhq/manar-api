import {
  Body,
  ConflictException,
  Controller,
  Logger,
  NotFoundException,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { CurrentAuth } from '../auth/auth-context';
import type { AuthContext } from '../auth/auth-context';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RequireRole } from '../auth/require-role.decorator';
import { RolesGuard } from '../auth/roles.guard';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { TemporalClientService } from '../temporal/temporal-client.service';
import { decideSignal } from '../temporal/workflows/approval.workflow';
import { parseBodyOrThrow } from '../agents/parse-body.util';
import { ApprovalRequestNotFoundError } from './approvals.errors';
import { ApprovalRequestService } from './approval-request.service';
import { DecideApprovalRequestSchema } from './approvals.validation';

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

  @Post(':id/decide')
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
