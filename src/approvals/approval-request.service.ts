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
import { computeParameterHash } from './parameter-hash.util';
import {
  redactApprovalParameters,
  type RedactedParameters,
} from './approval-parameter-redaction';
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
  /**
   * Release 2026-11-11 (brief §3.4) — the risk breakdown behind
   * `riskScore`, captured at request time so the reviewer sees the factors
   * rather than only the total. Deterministic and AI contributions stay
   * separately attributed; see `ApprovalRequest`'s schema doc comment for
   * why `aiAdvisoryScore: null` means "no signal was available" and never
   * "the AI scored it zero".
   */
  deterministicRiskScore: number;
  aiAdvisoryScore: number | null;
  riskReasonCodes: string[];
  taskRiskCeiling: number;
  /** `'policy_requires_approval'` or `'risk_ceiling_exceeded'` — `AuthorizationService`'s own `reason`, persisted rather than re-derived (see the column's schema doc comment for why deriving it is wrong). */
  requiredReason: string;
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
        deterministicRiskScore: input.deterministicRiskScore,
        aiAdvisoryScore: input.aiAdvisoryScore,
        riskReasonCodes: input.riskReasonCodes,
        taskRiskCeiling: input.taskRiskCeiling,
        requiredReason: input.requiredReason,
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

  /**
   * `GET /approvals/:id` (release 2026-11-11, brief §3.4) — the immutable,
   * safely redacted snapshot of the exact action a reviewer is being asked
   * to approve.
   *
   * This endpoint exists because the approval *binding* was already strong
   * — a one-use grant, atomic redemption, and a `parameterHash` over the
   * exact `{taskId, toolId, actionId, resource, params}` tuple — while the
   * human doing the approving was shown none of it. A cryptographic
   * binding to a snapshot nobody read is a weaker control than it appears.
   *
   * Three things are deliberate here:
   *
   * 1. **`parameterDigest` is recomputed, not stored.** It is the same
   *    value `GrantService` binds the eventual grant to, derived from the
   *    same function over the same row. Recomputing means the reviewer is
   *    shown a digest of what is actually in the database now, rather than
   *    a value that could have been written once and drifted.
   * 2. **Redaction is key-name based and says so.** See
   *    `approval-parameter-redaction.ts` — it is hygiene for the obvious
   *    case, not a DLP guarantee, and `redactedKeyPaths` tells the reviewer
   *    when something was withheld so a partial object is never read as a
   *    complete one.
   * 3. **`riskReasonCodes` is split by attribution rather than returned as
   *    one list.** `RiskEngine` prefixes AI-derived codes `ai_advisory_*`
   *    precisely so the two never blend; the split is done here so every
   *    consumer gets it right by default instead of each re-deriving it.
   *
   * `expectedEffect` reads the `ToolAction` row directly rather than going
   * through `ToolRegistryService`: it is a two-column read on the same
   * already-tenant-scoped client, and importing the tools module into the
   * approvals one to fetch `mutating`/`destructive`/`classification` would
   * couple them for no gain.
   */
  async getDetailOrThrow(
    tenantClient: TenantPrismaClient,
    id: string,
  ): Promise<ApprovalRequestDetail> {
    const row = await tenantClient.approvalRequest.findUnique({
      where: { id },
      include: {
        grant: true,
        decisions: { orderBy: { decidedAt: 'asc' } },
      },
    });
    if (!row) throw new ApprovalRequestNotFoundError(id);

    const action = await tenantClient.toolAction.findUnique({
      where: { id: row.actionId },
      select: {
        name: true,
        mutating: true,
        destructive: true,
        classification: true,
      },
    });

    const redacted = redactApprovalParameters(row.params);
    const reasonCodes = Array.isArray(row.riskReasonCodes)
      ? (row.riskReasonCodes as string[])
      : [];

    return {
      id: row.id,
      taskId: row.taskId,
      agentId: row.agentId,
      toolId: row.toolId,
      actionId: row.actionId,
      resource: row.resource,
      status: row.status,
      requestedAt: row.requestedAt,
      expiresAt: row.expiresAt,

      parameters: redacted,
      parameterDigest: computeParameterHash({
        taskId: row.taskId,
        toolId: row.toolId,
        actionId: row.actionId,
        resource: row.resource,
        params: row.params,
      }),

      riskScore: row.riskScore,
      deterministicRiskScore: row.deterministicRiskScore,
      aiAdvisoryScore: row.aiAdvisoryScore,
      taskRiskCeiling: row.taskRiskCeiling,
      requiredReason: row.requiredReason,
      deterministicReasonCodes: reasonCodes.filter(
        (code) => !code.startsWith('ai_advisory_'),
      ),
      aiAdvisoryReasonCodes: reasonCodes.filter((code) =>
        code.startsWith('ai_advisory_'),
      ),

      policyVersionId: row.policyVersionId,

      expectedEffect:
        action === null
          ? null
          : {
              actionName: action.name,
              mutating: action.mutating,
              destructive: action.destructive,
              classification: action.classification,
            },

      decisions: row.decisions.map((decision) => ({
        decision: decision.decision,
        approverId: decision.approverId,
        decidedAt: decision.decidedAt,
        reason: decision.reason,
      })),

      grantIssued: row.grant !== null,
      grantConsumedAt: row.grant?.consumedAt ?? null,
    };
  }
}

/** `GET /approvals/:id`'s shape — see `getDetailOrThrow`. */
export interface ApprovalRequestDetail {
  id: string;
  taskId: string;
  agentId: string;
  toolId: string;
  actionId: string;
  resource: string;
  status: string;
  requestedAt: Date;
  expiresAt: Date;

  parameters: RedactedParameters;
  /** The exact sha256 an issued grant is (or would be) bound to. */
  parameterDigest: string;

  riskScore: number;
  /** `null` on rows predating the breakdown migration — "not recorded", never zero. */
  deterministicRiskScore: number | null;
  /** `null` means no advisory signal was available, never "the AI scored zero". */
  aiAdvisoryScore: number | null;
  taskRiskCeiling: number | null;
  requiredReason: string | null;
  deterministicReasonCodes: string[];
  aiAdvisoryReasonCodes: string[];

  policyVersionId: string | null;

  /** `null` when the action row is no longer resolvable — reported as unknown rather than guessed. */
  expectedEffect: {
    actionName: string;
    mutating: boolean;
    destructive: boolean;
    classification: string;
  } | null;

  decisions: {
    decision: string;
    approverId: string;
    decidedAt: Date;
    /** The approver's own free-text reason, as recorded verbatim before any re-evaluation — see `ApprovalDecision`'s schema doc comment. */
    reason: string | null;
  }[];

  grantIssued: boolean;
  grantConsumedAt: Date | null;
}
