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
  status: 'APPROVED' | 'DENIED';
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
      return existing.status === 'APPROVED'
        ? { status: 'APPROVED', grantId: existing.grant?.id }
        : { status: 'DENIED' };
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
      await tenantClient.approvalRequest.update({
        where: { id: existing.id },
        data: { status: 'DENIED' },
      });
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

    const reevaluation = await this.reevaluateAndIssueGrant(
      tenantClient,
      input.tenantId,
      existing,
    );
    const grantId = reevaluation.grantId;

    await tenantClient.approvalRequest.update({
      where: { id: existing.id },
      data: { status: grantId ? 'APPROVED' : 'DENIED' },
    });

    if (grantId) {
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_APPROVED,
        actor: { type: 'human', id: input.approverId },
        data: {
          approvalRequestId: existing.id,
          decision: 'APPROVE',
          reason: input.reason ?? null,
        },
      });
    } else {
      // Section 27: the human clicked APPROVE, but re-evaluation at
      // approval time no longer supports it (task/agent no longer live,
      // policy now denies, or the execution limit was reached in the
      // meantime) — the *request's* final outcome is DENIED even though
      // the raw human decision (already recorded as an `ApprovalDecision`
      // row above) was APPROVE. Recorded as `approval.denied` since that's
      // what actually happened to this request, with `originalDecision`
      // carrying the human's real input for anyone reconstructing why.
      await this.auditService.recordSafely(tenantClient, input.tenantId, {
        eventType: AUDIT_EVENT_TYPES.APPROVAL_DENIED,
        actor: { type: 'human', id: input.approverId },
        data: {
          approvalRequestId: existing.id,
          decision: 'APPROVE',
          originalDecision: 'APPROVE',
          reason: reevaluation.failureReason ?? 'reevaluation_failed',
        },
      });
    }

    return grantId ? { status: 'APPROVED', grantId } : { status: 'DENIED' };
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

    await tenantClient.approvalRequest.update({
      where: { id: existing.id },
      data: { status: 'EXPIRED' },
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
   * `POST /agent/v1/tools/invoke`'s `grantToken` retry path (Section 80).
   * Verifies signature+expiry, then checks every binding invariant in
   * turn: the decoded claims match *this* request's
   * `agentId`/`taskId`/`toolId`/`actionId`/`resource` exactly, and —
   * critically — `parameterHash` recomputed from *this exact request's*
   * `params` matches the grant's own (the parameter-binding invariant).
   * Only then loads the `AuthorizationGrant` row itself and checks
   * unconsumed/unrevoked/unexpired. Re-checks task/agent liveness (the
   * fail-closed conditions that exist today) but does **not** re-run
   * `PolicyEngine`/`RiskEngine` or increment `executionCount` again —
   * those already happened once, at grant-issuance time
   * (`reevaluateAndIssueGrant`). On success, atomically marks the grant
   * consumed via a conditional `UPDATE ... WHERE consumedAt IS NULL` (the
   * same race-closing pattern `TasksService.incrementExecutionCount`
   * uses) — single-use, closing the approval-replay race for good: a
   * concurrent or later repeated use of the same token always loses it.
   */
  async validateAndConsumeGrant(
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

    const task = await tenantClient.task.findUnique({
      where: { id: input.taskId },
    });
    if (!task) return { valid: false, reason: 'task_not_found' };
    const liveness = await this.tasksService.evaluateFullLiveness(
      tenantClient,
      task,
      new Date(),
    );
    if (!liveness.ok) {
      return { valid: false, reason: liveness.reason ?? 'task_not_live' };
    }

    const agent = await tenantClient.agent.findUnique({
      where: { id: input.agentId },
    });
    if (!agent || agent.status !== 'ACTIVE') {
      return { valid: false, reason: 'agent_not_active' };
    }

    const consumeResult = await tenantClient.authorizationGrant.updateMany({
      where: { id: grant.id, consumedAt: null },
      data: { consumedAt: new Date() },
    });
    if (consumeResult.count === 0) {
      // Lost the single-use race against a concurrent use of this exact
      // token — Section 80's approval-replay invariant, enforced at the
      // database level, not just by the earlier in-memory check above.
      return { valid: false, reason: 'grant_already_consumed' };
    }

    return { valid: true, grantId: grant.id };
  }

  /**
   * Returns the new `AuthorizationGrant`'s id on success, or `grantId:
   * null` (with a `failureReason`) if re-evaluation no longer supports
   * approval — task/agent no longer live, policy now denies, or the
   * execution limit was reached in the meantime. `finalizeDecision` treats
   * a `null` `grantId` as `DENIED`. No grant is ever issued on this path.
   */
  private async reevaluateAndIssueGrant(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    approvalRequest: ApprovalRequestLike,
  ): Promise<{ grantId: string | null; failureReason?: string }> {
    const task = await tenantClient.task.findUnique({
      where: { id: approvalRequest.taskId },
    });
    if (!task) {
      this.logger.warn(
        `ApprovalRequest "${approvalRequest.id}" re-evaluation: task "${approvalRequest.taskId}" no longer exists`,
      );
      return { grantId: null, failureReason: 'task_not_found' };
    }

    const liveness = await this.tasksService.evaluateFullLiveness(
      tenantClient,
      task,
      new Date(),
    );
    if (!liveness.ok) {
      this.logger.warn(
        `ApprovalRequest "${approvalRequest.id}" re-evaluation failed: ${liveness.reason}`,
      );
      return { grantId: null, failureReason: liveness.reason };
    }

    const agent = await tenantClient.agent.findUnique({
      where: { id: approvalRequest.agentId },
    });
    if (!agent || agent.status !== 'ACTIVE') {
      this.logger.warn(
        `ApprovalRequest "${approvalRequest.id}" re-evaluation failed: agent "${approvalRequest.agentId}" is not ACTIVE`,
      );
      return { grantId: null, failureReason: 'agent_not_active' };
    }

    // Section 27: re-run PolicyEngine/RiskEngine against *current* state
    // rather than trusting the original decision — this is what catches a
    // policy republished stricter mid-flight even though a human already
    // clicked approve.
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
      const reason = policyResult.failureReason
        ? 'policy_evaluation_failed'
        : 'policy_denied';
      this.logger.warn(
        `ApprovalRequest "${approvalRequest.id}" re-evaluation failed: policy now denies this action (${reason})`,
      );
      return { grantId: null, failureReason: reason };
    }

    const riskResult = await this.riskEngine.score(tenantClient, {
      toolId: approvalRequest.toolId,
      actionId: approvalRequest.actionId,
      resource: approvalRequest.resource,
      task,
      policyMatch: policyResult.matchedRule,
    });

    // The same atomic, race-closing increment AuthorizationService's own
    // ALLOW path performs — for an approved action, this happens exactly
    // once, here, at grant-issuance time (never again when the grant is
    // later consumed — see validateAndConsumeGrant's own doc comment).
    const incremented = await this.tasksService.incrementExecutionCount(
      tenantClient,
      task,
    );
    if (!incremented) {
      this.logger.warn(
        `ApprovalRequest "${approvalRequest.id}" re-evaluation failed: task "${task.id}" execution limit reached`,
      );
      return { grantId: null, failureReason: 'task_execution_limit_reached' };
    }

    const parameterHash = computeParameterHash({
      taskId: approvalRequest.taskId,
      toolId: approvalRequest.toolId,
      actionId: approvalRequest.actionId,
      resource: approvalRequest.resource,
      params: approvalRequest.params,
    });

    const issuedAt = new Date();
    const ttlMs = this.configService.get('APPROVAL_GRANT_TTL_MS', {
      infer: true,
    });
    const expiresAt = new Date(issuedAt.getTime() + ttlMs);

    const grant = await tenantClient.authorizationGrant.create({
      data: {
        id: randomUUID(),
        approvalRequestId: approvalRequest.id,
        taskId: approvalRequest.taskId,
        agentId: approvalRequest.agentId,
        toolId: approvalRequest.toolId,
        actionId: approvalRequest.actionId,
        resource: approvalRequest.resource,
        parameterHash,
        policyVersionId: policyResult.policyVersionId ?? null,
        riskScore: riskResult.finalRiskScore,
        issuedAt,
        expiresAt,
      },
    });

    // Phase 9a: `approval.grant_issued` — actor `system` (not the
    // approving human): this is the automated re-evaluation Activity's own
    // decision to actually mint a grant, distinct from the human's raw
    // APPROVE decision (`approval.approved`, recorded by the caller,
    // `finalizeDecision`, with actor `human`). Never includes the signed
    // grant token itself — no such string is ever persisted anywhere (see
    // `GrantService.signGrantTokenFor`'s doc comment); only the same
    // fields the `AuthorizationGrant` row itself carries.
    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_ISSUED,
      actor: { type: 'system', id: 'system:approval-workflow' },
      data: {
        approvalRequestId: approvalRequest.id,
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

    return { grantId: grant.id };
  }
}
