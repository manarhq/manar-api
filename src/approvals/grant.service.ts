import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { AppConfig } from '../config/env.validation';
import { TasksService } from '../tasks/tasks.service';
import { PolicyEngine } from '../policy/policy-engine.service';
import { RiskEngine } from '../risk/risk-engine.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { ApprovalRequestNotFoundError } from './approvals.errors';
import { computeParameterHash } from './parameter-hash.util';
import { signGrantToken, verifyGrantToken } from './grant-token.util';

export interface FinalizeDecisionInput {
  tenantId: string;
  approvalRequestId: string;
  decision: 'APPROVE' | 'DENY';
  approverId: string;
  reason?: string;
}

export interface FinalizeDecisionResult {
  /** EXPIRED: the request expired (timeout, or superseded on the MCP door) before this decision landed. */
  status: 'APPROVED' | 'DENIED' | 'EXPIRED';
  grantId?: string;
}

export interface ValidateGrantInput {
  tenantId: string;
  agentId: string;
  taskId: string;
  toolId: string;
  actionId: string;
  resource: string;
  params: unknown;
  grantToken: string;
}

export type GrantValidationResult =
  { valid: true; grantId: string } | { valid: false; reason: string };

interface ApprovalRequestLike {
  id: string;
  taskId: string;
  agentId: string;
  toolId: string;
  actionId: string;
  resource: string;
  params: unknown;
}

/**
 * The re-evaluation + grant-issuance logic behind `ApprovalWorkflow`'s
 * `finalizeApprovalDecision` Activity, and the grant-validation logic
 * behind `POST /agent/v1/tools/invoke`'s `grantToken` retry path (Phase 8,
 * Sections 27/28/31/80 — see docs/approvals.md). Deliberately one service
 * for both halves: issuance and validation share the exact same
 * `parameterHash`/liveness notions, and keeping them together is what
 * makes it structurally obvious neither one drifts from the other.
 */
@Injectable()
export class GrantService {
  private readonly logger = new Logger(GrantService.name);

  constructor(
    private readonly tasksService: TasksService,
    private readonly policyEngine: PolicyEngine,
    private readonly riskEngine: RiskEngine,
    private readonly configService: ConfigService<AppConfig, true>,
    private readonly auditService: AuditService,
  ) {}

  /**
   * The Activity behind `ApprovalWorkflow`'s `decide`-signal branch
   * (Section 27/28: an Activity does this, never workflow code). Records
   * the human's raw `ApprovalDecision` first, unconditionally; for
   * `APPROVE`, only then re-evaluates task/agent liveness and re-runs
   * `PolicyEngine`/`RiskEngine` against *current* state — never trusting
   * the original, possibly-stale decision (Section 27) — before ever
   * issuing an `AuthorizationGrant`. Idempotent: a Temporal Activity retry
   * for the same `approvalRequestId` observes the already-terminal
   * `ApprovalRequest.status` and returns the prior outcome rather than
   * double-recording a decision or double-issuing a grant.
   */
  async finalizeDecision(
    tenantClient: TenantPrismaClient,
    input: FinalizeDecisionInput,
  ): Promise<FinalizeDecisionResult> {
    const existing = await tenantClient.approvalRequest.findUnique({
      where: { id: input.approvalRequestId },
      include: { grant: true },
    });
    if (!existing) {
      throw new ApprovalRequestNotFoundError(input.approvalRequestId);
    }

    if (existing.status !== 'PENDING') {
      this.logger.warn(
        `finalizeDecision called for ApprovalRequest "${existing.id}" whose status is already "${existing.status}" — returning the existing outcome (Activity retry, or a bug elsewhere) rather than re-deciding it`,
      );
      return outcomeOf(existing);
    }

    await tenantClient.approvalDecision.create({
      data: {
        approvalRequestId: existing.id,
        approverId: input.approverId,
        decision: input.decision,
        reason: input.reason ?? null,
      },
    });

    if (input.decision === 'DENY') {
      if (!(await this.claimPending(tenantClient, existing.id, 'DENIED'))) {
        return this.lostTo(tenantClient, existing.id);
      }
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_DENIED,
        actor: { type: 'human', id: input.approverId },
        data: {
          approvalRequestId: existing.id,
          decision: 'DENY',
          reason: input.reason ?? null,
        },
      });
      return { status: 'DENIED' };
    }

    // Read-only re-evaluation first; then, in one transaction, the
    // conditional PENDING -> APPROVED claim, the execution count and the
    // grant. A request that expired or was decided in between keeps its
    // state and gets no grant.
    const reevaluation = await this.reevaluate(
      tenantClient,
      input.tenantId,
      existing,
    );
    const issued = await tenantClient.$transaction(async (tx) => {
      if (!reevaluation.ok) {
        const claimed = await this.claimPending(
          tx,
          existing.id,
          'DENIED',
          reevaluation.failureReason ?? 'reevaluation_failed',
        );
        return claimed
          ? {
              lost: false as const,
              grant: null,
              failureReason: reevaluation.failureReason,
            }
          : { lost: true as const };
      }
      if (!(await this.claimPending(tx, existing.id, 'APPROVED'))) {
        return { lost: true as const };
      }
      // The same atomic, race-closing increment AuthorizationService's own
      // ALLOW path performs. For an approved action this happens exactly
      // once, here, at grant-issuance time (never again at redemption; see
      // AuthorizationService.authorizeRedemption).
      const incremented = await this.tasksService.incrementExecutionCount(
        tx,
        reevaluation.task,
      );
      if (!incremented) {
        await tx.approvalRequest.update({
          where: { id: existing.id },
          data: { status: 'DENIED', endReason: 'task_execution_limit_reached' },
        });
        return {
          lost: false as const,
          grant: null,
          failureReason: 'task_execution_limit_reached',
        };
      }
      const grant = await this.createGrant(tx, existing, reevaluation);
      return { lost: false as const, grant, failureReason: undefined };
    });

    if (issued.lost) return this.lostTo(tenantClient, existing.id);

    if (issued.grant) {
      await this.auditGrantIssued(tenantClient, input.tenantId, issued.grant);
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_APPROVED,
        actor: { type: 'human', id: input.approverId },
        data: {
          approvalRequestId: existing.id,
          decision: 'APPROVE',
          reason: input.reason ?? null,
        },
      });
      return { status: 'APPROVED', grantId: issued.grant.id };
    }

    this.logger.warn(
      `ApprovalRequest "${existing.id}" re-evaluation failed: ${issued.failureReason}`,
    );
    // Section 27: the human clicked APPROVE, but re-evaluation at approval
    // time no longer supports it (task/agent no longer live, policy now
    // denies, or the execution limit was reached in the meantime) — the
    // *request's* final outcome is DENIED even though the raw human decision
    // (already recorded as an `ApprovalDecision` row above) was APPROVE.
    // Recorded as `approval.denied` since that's what actually happened to
    // this request, with `originalDecision` carrying the human's real input.
    await this.auditService.recordSafely(tenantClient, input.tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_DENIED,
      actor: { type: 'human', id: input.approverId },
      data: {
        approvalRequestId: existing.id,
        decision: 'APPROVE',
        originalDecision: 'APPROVE',
        reason: issued.failureReason ?? 'reevaluation_failed',
      },
    });
    return { status: 'DENIED' };
  }

  /** PENDING -> `status`, only if still PENDING. False: someone else moved it first. */
  private async claimPending(
    client: Pick<TenantPrismaClient, 'approvalRequest'>,
    id: string,
    status: 'APPROVED' | 'DENIED',
    /** Why Manar, not the person, decided: a re-evaluation failure. */
    endReason?: string,
  ): Promise<boolean> {
    const { count } = await client.approvalRequest.updateMany({
      where: { id, status: 'PENDING' },
      data: endReason ? { status, endReason } : { status },
    });
    return count === 1;
  }

  /** This decision lost the race: report whatever state the request is in now. */
  private async lostTo(
    tenantClient: TenantPrismaClient,
    id: string,
  ): Promise<FinalizeDecisionResult> {
    const current = await tenantClient.approvalRequest.findUnique({
      where: { id },
      include: { grant: true },
    });
    this.logger.warn(
      `ApprovalRequest "${id}" changed to "${current?.status}" while a decision was being applied; that state stands`,
    );
    return current ? outcomeOf(current) : { status: 'EXPIRED' };
  }

  /**
   * The Activity behind `ApprovalWorkflow`'s timeout branch. Idempotent,
   * same reasoning as `finalizeDecision`.
   */
  async expire(
    tenantClient: TenantPrismaClient,
    approvalRequestId: string,
  ): Promise<void> {
    const existing = await tenantClient.approvalRequest.findUnique({
      where: { id: approvalRequestId },
    });
    if (!existing) {
      throw new ApprovalRequestNotFoundError(approvalRequestId);
    }
    if (existing.status !== 'PENDING') return;

    // Conditional: a decision that landed after the read above wins.
    await tenantClient.approvalRequest.updateMany({
      where: { id: existing.id, status: 'PENDING' },
      data: { status: 'EXPIRED', endReason: 'no_answer' },
    });
  }

  /**
   * Re-derives an already-issued `AuthorizationGrant`'s signed token from
   * its persisted fields (deterministic — see `signGrantToken`'s doc
   * comment for why no token string is itself stored).
   */
  async signGrantTokenFor(
    tenantId: string,
    grant: {
      id: string;
      agentId: string;
      taskId: string;
      toolId: string;
      actionId: string;
      resource: string;
      parameterHash: string;
      issuedAt: Date;
      expiresAt: Date;
    },
  ): Promise<string> {
    const secret = this.configService.get('APPROVAL_GRANT_SIGNING_SECRET', {
      infer: true,
    });
    return signGrantToken(
      {
        jti: grant.id,
        tenantId,
        agentId: grant.agentId,
        taskId: grant.taskId,
        toolId: grant.toolId,
        actionId: grant.actionId,
        resource: grant.resource,
        parameterHash: grant.parameterHash,
        issuedAt: grant.issuedAt,
        expiresAt: grant.expiresAt,
      },
      secret,
    );
  }

  /**
   * The MCP door's redemption (ADR-0007): an MCP `tools/call` cannot carry a
   * grant token, so the server finds the grant itself. Returns the signed
   * token of the newest unconsumed, unrevoked, unexpired grant issued for
   * exactly this agent, task, tool, action, resource and parameter hash, or
   * null. The token never leaves the server: the caller hands it to
   * `verifyGrant` and `authorizeRedemption` exactly as if the agent had sent
   * it, so single use and full revalidation (ADR-0006) are unchanged.
   */
  async findRedeemableGrantToken(
    tenantClient: TenantPrismaClient,
    input: Omit<ValidateGrantInput, 'grantToken'>,
  ): Promise<string | null> {
    const grant = await tenantClient.authorizationGrant.findFirst({
      where: {
        agentId: input.agentId,
        taskId: input.taskId,
        toolId: input.toolId,
        actionId: input.actionId,
        resource: input.resource,
        parameterHash: computeParameterHash(input),
        consumedAt: null,
        revokedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { issuedAt: 'desc' },
    });
    return grant ? this.signGrantTokenFor(input.tenantId, grant) : null;
  }

  /**
   * `POST /agent/v1/tools/invoke`'s `grantToken` retry path (Section 80),
   * first half: is this the grant for *this exact request*? Verifies
   * signature and expiry, then that the decoded claims match this request's
   * `agentId`/`taskId`/`toolId`/`actionId`/`resource` exactly and that
   * `parameterHash` recomputed from *this request's* `params` matches (the
   * parameter-binding invariant), then that the persisted `AuthorizationGrant`
   * row agrees and is unconsumed, unrevoked and unexpired.
   *
   * It does not consume the grant. The second half,
   * `AuthorizationService.authorizeRedemption`, re-runs the full decision
   * against current state (S6/F7) and, only if that still allows, consumes
   * the grant with a conditional `UPDATE ... WHERE consumedAt IS NULL` in the
   * same transaction as the `Decision` record (ADR-003), so single use is
   * still enforced by the database: a concurrent or repeated use loses.
   */
  async verifyGrant(
    tenantClient: TenantPrismaClient,
    input: ValidateGrantInput,
  ): Promise<GrantValidationResult> {
    const secret = this.configService.get('APPROVAL_GRANT_SIGNING_SECRET', {
      infer: true,
    });

    let claims;
    try {
      claims = await verifyGrantToken(input.grantToken, secret);
    } catch {
      return { valid: false, reason: 'grant_invalid' };
    }

    const parameterHash = computeParameterHash({
      taskId: input.taskId,
      toolId: input.toolId,
      actionId: input.actionId,
      resource: input.resource,
      params: input.params,
    });

    if (
      claims.tenantId !== input.tenantId ||
      claims.agentId !== input.agentId ||
      claims.taskId !== input.taskId ||
      claims.toolId !== input.toolId ||
      claims.actionId !== input.actionId ||
      claims.resource !== input.resource ||
      claims.parameterHash !== parameterHash
    ) {
      // Deliberately one generic reason for every mismatch kind (identity
      // mismatch or parameter mismatch alike) — never leaking which
      // specific field differed, the same posture
      // AuthorizationService's own OpenFGA-denial reason takes.
      return { valid: false, reason: 'grant_mismatch' };
    }

    const grant = await tenantClient.authorizationGrant.findUnique({
      where: { id: claims.jti },
    });
    if (!grant) return { valid: false, reason: 'grant_not_found' };
    if (grant.revokedAt) return { valid: false, reason: 'grant_revoked' };
    if (grant.consumedAt) {
      return { valid: false, reason: 'grant_already_consumed' };
    }
    if (grant.expiresAt.getTime() <= Date.now()) {
      return { valid: false, reason: 'grant_expired' };
    }
    if (
      grant.agentId !== input.agentId ||
      grant.taskId !== input.taskId ||
      grant.toolId !== input.toolId ||
      grant.actionId !== input.actionId ||
      grant.resource !== input.resource ||
      grant.parameterHash !== parameterHash
    ) {
      // Defense in depth: the signed claims already agreed with the
      // request above, but the persisted row is the actual source of
      // truth for consumption/expiry — never trust the token alone.
      return { valid: false, reason: 'grant_mismatch' };
    }

    return { valid: true, grantId: grant.id };
  }

  /**
   * Section 27: re-evaluates task/agent liveness and re-runs
   * PolicyEngine/RiskEngine against *current* state rather than trusting the
   * original decision — this is what catches a policy republished stricter
   * mid-flight even though a human already clicked approve. Reads only; the
   * caller writes (claim, execution count, grant) in one transaction.
   */
  private async reevaluate(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    approvalRequest: ApprovalRequestLike,
  ): Promise<Reevaluation> {
    const task = await tenantClient.task.findUnique({
      where: { id: approvalRequest.taskId },
    });
    if (!task) return { ok: false, failureReason: 'task_not_found' };

    const liveness = await this.tasksService.evaluateFullLiveness(
      tenantClient,
      tenantId,
      task,
      new Date(),
    );
    if (!liveness.ok) {
      return { ok: false, failureReason: liveness.reason ?? 'task_not_live' };
    }

    const agent = await tenantClient.agent.findUnique({
      where: { id: approvalRequest.agentId },
    });
    if (!agent || agent.status !== 'ACTIVE') {
      return { ok: false, failureReason: 'agent_not_active' };
    }

    const policyResult = await this.policyEngine.evaluate(
      tenantClient,
      tenantId,
      {
        toolId: approvalRequest.toolId,
        actionId: approvalRequest.actionId,
        resource: approvalRequest.resource,
      },
    );
    if (policyResult.effect === 'DENY') {
      return {
        ok: false,
        failureReason: policyResult.failureReason
          ? 'policy_evaluation_failed'
          : 'policy_denied',
      };
    }

    const riskResult = await this.riskEngine.score(tenantClient, {
      tenantId,
      toolId: approvalRequest.toolId,
      actionId: approvalRequest.actionId,
      resource: approvalRequest.resource,
      task,
      agentId: approvalRequest.agentId,
      policyMatch: policyResult.matchedRule,
    });

    return {
      ok: true,
      task,
      policyVersionId: policyResult.policyVersionId ?? null,
      riskScore: riskResult.riskScore,
    };
  }

  private async createGrant(
    client: Pick<TenantPrismaClient, 'authorizationGrant'>,
    approvalRequest: ApprovalRequestLike,
    reevaluation: Extract<Reevaluation, { ok: true }>,
  ) {
    const issuedAt = new Date();
    const ttlMs = this.configService.get('APPROVAL_GRANT_TTL_MS', {
      infer: true,
    });
    return client.authorizationGrant.create({
      data: {
        id: randomUUID(),
        approvalRequestId: approvalRequest.id,
        taskId: approvalRequest.taskId,
        agentId: approvalRequest.agentId,
        toolId: approvalRequest.toolId,
        actionId: approvalRequest.actionId,
        resource: approvalRequest.resource,
        parameterHash: computeParameterHash({
          taskId: approvalRequest.taskId,
          toolId: approvalRequest.toolId,
          actionId: approvalRequest.actionId,
          resource: approvalRequest.resource,
          params: approvalRequest.params,
        }),
        policyVersionId: reevaluation.policyVersionId,
        riskScore: reevaluation.riskScore,
        issuedAt,
        expiresAt: new Date(issuedAt.getTime() + ttlMs),
      },
    });
  }

  /**
   * Phase 9a: `approval.grant_issued` — actor `system` (not the approving
   * human): the automated re-evaluation's own decision to mint a grant,
   * distinct from the human's raw APPROVE (`approval.approved`). Never
   * includes the signed grant token (no such string is persisted; see
   * `signGrantTokenFor`).
   */
  private async auditGrantIssued(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    grant: Awaited<ReturnType<GrantService['createGrant']>>,
  ): Promise<void> {
    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_ISSUED,
      actor: { type: 'system', id: 'system:approval-workflow' },
      data: {
        approvalRequestId: grant.approvalRequestId,
        grantId: grant.id,
        taskId: grant.taskId,
        agentId: grant.agentId,
        toolId: grant.toolId,
        actionId: grant.actionId,
        resource: grant.resource,
        riskScore: grant.riskScore,
        policyVersionId: grant.policyVersionId,
        issuedAt: grant.issuedAt,
        expiresAt: grant.expiresAt,
      },
    });
  }
}

type Reevaluation =
  | { ok: false; failureReason: string }
  | {
      ok: true;
      task: NonNullable<
        Awaited<ReturnType<TenantPrismaClient['task']['findUnique']>>
      >;
      policyVersionId: string | null;
      riskScore: number;
    };

function outcomeOf(request: {
  status: string;
  grant?: { id: string } | null;
}): FinalizeDecisionResult {
  if (request.status === 'APPROVED') {
    return { status: 'APPROVED', grantId: request.grant?.id };
  }
  return request.status === 'EXPIRED'
    ? { status: 'EXPIRED' }
    : { status: 'DENIED' };
}
