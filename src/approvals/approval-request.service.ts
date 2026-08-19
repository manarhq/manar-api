import { Injectable } from '@nestjs/common';
import type {
  Prisma,
  PrismaClient as TenantPrismaClient,
} from '../generated/tenant-client/client';
import {
  DecodedCursor,
  cursorWhereClause,
  toCursorPage,
} from '../common/pagination/cursor-pagination';
import { ApprovalRequestNotFoundError } from './approvals.errors';

export interface ListApprovalRequestsInput {
  /** Section 65's approvals list filter. */
  status?: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED';
  limit: number;
  cursor?: DecodedCursor;
}

export interface CreateApprovalRequestInput {
  taskId: string;
  agentId: string;
  toolId: string;
  actionId: string;
  resource: string;
  /** The exact `params` submitted to `POST /agent/v1/tools/invoke` — see `ApprovalRequest`'s schema doc comment. */
  params: unknown;
  riskScore: number;
  /** Null when the `REQUIRE_APPROVAL` decision came purely from `RiskEngine`'s score exceeding `task.riskCeiling`, with no policy rule matching at all. */
  policyVersionId: string | null;
  expiresAt: Date;
  temporalWorkflowId: string;
}

/**
 * `ApprovalRequest` creation + lookup (Phase 8, Sections 27/28/31 — see
 * docs/approvals.md). Used by both the human-facing/agent-facing HTTP
 * processes (`ToolInvokeController` creates one the moment
 * `AuthorizationService` yields `REQUIRE_APPROVAL`;
 * `AgentApprovalsController`/`ApprovalsController` read one) and — since
 * the worker process bootstraps the exact same Nest providers (see
 * `src/worker.main.ts`) — `GrantService`'s Activities. One implementation
 * either side calls, never two copies of "how to read/write an
 * ApprovalRequest row."
 */
@Injectable()
export class ApprovalRequestService {
  async create(
    tenantClient: TenantPrismaClient,
    input: CreateApprovalRequestInput,
  ) {
    return tenantClient.approvalRequest.create({
      data: {
        taskId: input.taskId,
        agentId: input.agentId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        params: input.params as Prisma.InputJsonValue,
        riskScore: input.riskScore,
        policyVersionId: input.policyVersionId,
        expiresAt: input.expiresAt,
        temporalWorkflowId: input.temporalWorkflowId,
      },
    });
  }

  /** Includes the issued `AuthorizationGrant`, if any (`GET /agent/v1/approvals/:id`'s own use case — no grant exists until `status` is `APPROVED`). */
  async getOrThrow(tenantClient: TenantPrismaClient, id: string) {
    const row = await tenantClient.approvalRequest.findUnique({
      where: { id },
      include: { grant: true },
    });
    if (!row) throw new ApprovalRequestNotFoundError(id);
    return row;
  }

  /**
   * `GET /approvals` (Phase 11b Part 1) — cursor-paginated, newest first,
   * with the one filter Section 65's approval queue actually needs
   * (`status` — an operator's queue view is "show me PENDING", not a
   * general browse). Ordered by `requestedAt` (this model's own creation
   * timestamp field name — see `ApprovalRequest.requestedAt`'s schema doc
   * comment), not `createdAt`.
   */
  async listApprovalRequests(
    tenantClient: TenantPrismaClient,
    input: ListApprovalRequestsInput,
  ) {
    const where = {
      ...(input.status ? { status: input.status } : {}),
      ...cursorWhereClause('requestedAt', input.cursor),
    };
    const rows = await tenantClient.approvalRequest.findMany({
      where,
      orderBy: [{ requestedAt: 'desc' }, { id: 'desc' }],
      take: input.limit + 1,
    });
    return toCursorPage(rows, input.limit, (row) => row.requestedAt);
  }
}
