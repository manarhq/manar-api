import { randomUUID } from 'node:crypto';
import { HttpException, Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import { TaskNotFoundError } from '../tasks/tasks.errors';
import { PolicyEngine } from '../policy/policy-engine.service';
import { RiskEngine } from '../risk/risk-engine.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { CatalogService } from '../platform/catalog.service';
import { parseToolActions } from './grant-triples';
import {
  ENFORCEMENT_DEPENDENCY_UNAVAILABLE,
  failClosed,
} from '../common/fail-closed/fail-closed';
import { computeParameterHash } from '../approvals/parameter-hash.util';
import { getCorrelationId } from '../logging/correlation-id.store';
import {
  ANY_RESOURCE_PATTERN,
  agentObjectId,
  grantObjectId,
} from './openfga-object-id.util';
import { OpenFgaClientService } from './openfga-client.service';
import type { AuthorizeRequest } from './authorize-request.validation';
import { recordDecision } from '../metrics/metrics';
import {
  findLiveAllowGrant,
  markAllowGrantUsed,
} from '../approvals/allow-grants';

type Verdict =
  | { decision: 'ALLOW' }
  | { decision: 'DENY'; reason: string }
  | {
      decision: 'APPROVAL_REQUIRED';
      reason: string;
      riskScore: number;
      /**
       * Phase 8: the published `PolicyVersion` whose rule produced this
       * decision — `null` when it came purely from `RiskEngine`'s score
       * exceeding `task.riskCeiling` with no policy rule matching at all
       * (see `PolicyEvaluationResult`'s doc comment). `ToolInvokeController`
       * carries this into the `ApprovalRequest` it creates
       * (`docs/approvals.md`) — `AuthorizeController`'s own response is
       * unaffected in shape for existing callers, since this is purely an
       * additive field on an already-typed-generically response.
       */
      policyVersionId: string | null;

      /**
       * Release 2026-11-11 (brief §3.4): the risk *breakdown*, so
       * `ToolInvokeController` can persist it onto the `ApprovalRequest`
       * and a human reviewer can see why approval was required rather than
       * only that a number crossed a line.
       *
       * `RiskEngine` has always computed these; until now they reached
       * only the structured log and the `authorization.pending_approval`
       * audit event, neither of which the approvals UI can join to a
       * request. Deterministic and AI contributions stay separately
       * attributed here for the same reason `RiskScoreResult` keeps them
       * apart — a blended score is not reviewable.
       */
      deterministicRiskScore: number;
      riskReasonCodes: string[];
      /** The `Task.riskCeiling` `riskScore` was actually compared against. */
      riskCeiling: number;
    };

/**
 * The pipeline's answer plus the id of the `Decision` row that recorded it
 * (ADR-003). Callers execute only under a `decisionId`.
 */
export type AuthorizeDecision = Verdict & { decisionId: string };

export type DecisionChannel = 'REST' | 'MCP' | 'AUTHORIZE';

export interface DecisionContext {
  channel: DecisionChannel;
  /**
   * Set by the host authorize path (`/host/v1/authorize`): the device the request comes from. An
   * "Approve for 8 hours" grant is then looked up for the device, otherwise for the agent.
   */
  hostId?: string;
  /** The action's parameters: hashed into `Decision.inputsHash`, never stored. */
  params?: unknown;
}

export type DecisionStage = 'REQUEST' | 'GRANT_REDEMPTION';

type DecisionRecordKind =
  { stage: 'REQUEST' } | { stage: 'GRANT_REDEMPTION'; grantId?: string };

/** What `GrantService.verifyGrant` concluded about the presented grant token. */
export type GrantCheck =
  { valid: true; grantId: string } | { valid: false; reason: string };

/** What `evaluate` concluded, before anything is written. */
interface Evaluation {
  verdict: Verdict;
  /** Extra fields for the audit event ("enough data to reconstruct why"). */
  audit: Record<string, unknown>;
  policyId?: string;
  policyVersionId?: string;
  riskScore?: number;
  riskReasonCodes?: string[];
  /** Present on ALLOW: the task whose execution count the commit increments. */
  task?: TaskRecord;
}

function deny(
  reason: string,
  audit: Record<string, unknown> = {},
  policy: Pick<Evaluation, 'policyId' | 'policyVersionId'> = {},
): Evaluation {
  return { verdict: { decision: 'DENY', reason }, audit, ...policy };
}

/** A client-supplied `x-correlation-id` is stored only if it is a sane id. */
function correlationIdForRecord(): string {
  const id = getCorrelationId();
  return id && /^[\w.:-]{1,128}$/.test(id) ? id : randomUUID();
}

/**
 * `POST /agent/v1/authorize`'s pipeline (Section 22 — fail-closed at every
 * step; if any check can't be evaluated trustworthily, DENY). Implements
 * the design spec's 6 steps exactly, plus the kill-switch phase's own
 * mandatory step 0 (Section 32 — see docs/kill-switches.md):
 *
 *   0. Kill switches: platform (control DB, cross-tenant) → tenant →
 *      requesting agent → any `AgentGroup` it belongs to → the specific
 *      `Tool` being invoked (only if `request.toolId` resolves against a
 *      registered `Tool.name` — this endpoint's `toolId` is always known
 *      by this point, unlike credential-broker registry resolution, which
 *      happens later on the ALLOW path; see `KillSwitchService.checkAll`).
 *      Deliberately runs BEFORE the task is even resolved (step 1) — none
 *      of these five checks need the task at all, and this is the
 *      cheapest, most fundamental "don't bother evaluating anything else"
 *      gate in the whole pipeline, exactly as the design spec asks.
 *   1. Resolve the Task, confirm `assignedAgentId` matches the
 *      mTLS-authenticated agent.
 *   2. Walk the FULL ancestor chain, confirm every ancestor is
 *      ACTIVE/unexpired/under its own execution limit — this is Section
 *      20's real-time revocation-cascade mechanism: revoking any ancestor
 *      immediately denies every descendant's next authorize call, with no
 *      cascade write ever touching the descendant.
 *   3. Confirm the task itself is ACTIVE/unexpired/under its own limit.
 *   4. Check `forbiddenActions` — an explicit deny short-circuits to DENY
 *      before OpenFGA is ever consulted.
 *   5. OpenFGA `check()` for the specific tool_action/resource against
 *      this task's grant tuples (tried against both the exact resource and
 *      the `"*"` "any resource for this tool action" wildcard grant — see
 *      docs/authorization-model.md's known-limitation note).
 *   6. On OpenFGA ALLOW, `PolicyEngine.evaluate` (Phase 6, Sections 21-22)
 *      — an extra, org-defined restriction layered *on top of* the
 *      already-permitted action above; it never re-decides steps 1-5. A
 *      policy `DENY` short-circuits to DENY immediately.
 *   7. `RiskEngine.score` (Phase 6) — a deterministic 0-100 risk score.
 *      `APPROVAL_REQUIRED` if the matched policy's own effect says so, OR
 *      the score exceeds this task's `riskCeiling`.
 *   8. Otherwise ALLOW: atomically increment `executionCount` — a
 *      conditional `UPDATE` that also closes the race against a
 *      concurrent request exhausting `maxExecutions` between step 3's read
 *      and this write.
 *
 * Steps 1-4 return a specific, non-leaky reason (deterministic app-layer
 * state, safe to expose). Step 5's DENY is deliberately generic
 * (`not_authorized`) — never surfacing *why* OpenFGA denied, so a caller
 * can't probe the shape of the authorization model. An OpenFGA outage
 * (network failure, wrong port, container down, or no answer within
 * OPENFGA_CHECK_TIMEOUT_MS) is caught and treated as DENY with the product
 * rule's reason (`enforcement_dependency_unavailable`) — never as ALLOW, and
 * never as an unhandled 5xx that could be mistaken for anything but a
 * definite non-ALLOW. Steps 6-7 (Phase 6) are inserted strictly *after*
 * Phase 5's own OpenFGA check and *before* its `executionCount` increment
 * — none of Phase 5's steps 1-5 are touched. `APPROVAL_REQUIRED` is a real,
 * stable decision from this phase onward, but this phase implements no
 * path to ever fulfil one (Phase 8) — it's correctly a dead end for now.
 * See docs/policy-model.md.
 *
 * ADR-003 (security finding S1): `evaluate` only reads. Its verdict is then
 * written as a `Decision` row by `commit`, and only after that commit does
 * the caller get an answer it can act on. For ALLOW, step 8's increment and
 * the `Decision` insert are one transaction. If the decision cannot be
 * written the request fails closed with 503 `enforcement_dependency_unavailable`
 * and nothing executes. Audit events are recorded after the commit and
 * carry the `decisionId`.
 */
@Injectable()
export class AuthorizationService {
  private readonly logger = new Logger(AuthorizationService.name);

  constructor(
    private readonly tasksService: TasksService,
    private readonly openFga: OpenFgaClientService,
    private readonly policyEngine: PolicyEngine,
    private readonly riskEngine: RiskEngine,
    private readonly auditService: AuditService,
    private readonly killSwitchService: KillSwitchService,
    private readonly catalog: CatalogService,
  ) {}

  /**
   * Any exception escaping the pipeline below (a tenant-DB or control-DB
   * error in a kill-switch or task lookup, `AncestorChainTooDeepError`, a
   * dangling parent, malformed stored actions) is a DENY with reason
   * `enforcement_dependency_unavailable`, recorded like any other decision,
   * never a bare 500 (Gate 0 findings S32 and S61). A failure to record the
   * decision itself is a 503.
   */
  async authorize(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    authenticatedAgentId: string,
    request: AuthorizeRequest,
    context: DecisionContext = { channel: 'AUTHORIZE' },
  ): Promise<AuthorizeDecision> {
    const startedAt = process.hrtime.bigint();
    const evaluation = await this.evaluateFailClosed(
      tenantClient,
      tenantId,
      authenticatedAgentId,
      request,
      'REQUEST',
      context.hostId,
    );
    return this.commit(
      tenantClient,
      tenantId,
      authenticatedAgentId,
      request,
      context,
      evaluation,
      { stage: 'REQUEST' },
      startedAt,
    );
  }

  /**
   * Security finding S6/F7 (spec §6.2): redeeming an approval grant re-runs
   * the whole pipeline against current state, never trusting the decision
   * that was true when the human approved. Kill switches at every level,
   * AI-system suspension, task liveness and TTL (ancestors included),
   * assignment, forbidden actions, OpenFGA and the current policy version
   * are all evaluated again; signature, expiry, revocation, single use and
   * parameter binding were checked by `GrantService.verifyGrant` (`grant`).
   *
   * Differences from a first attempt, both because a human has already
   * approved this exact request: a policy `APPROVAL_REQUIRED` and a risk
   * score above the task ceiling do not block, only `DENY` does; and the
   * execution count is not incremented again (it was at grant issuance), so
   * the task's own limit does not count this request twice.
   *
   * ALLOW consumes the grant (`UPDATE ... WHERE consumedAt IS NULL AND
   * revokedAt IS NULL AND expiresAt > now`) in the same transaction as the
   * `Decision` insert; losing that race records DENY `grant_already_consumed`.
   * Every outcome, including an invalid grant, is a recorded `Decision`.
   */
  async authorizeRedemption(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    authenticatedAgentId: string,
    request: AuthorizeRequest,
    context: DecisionContext,
    grant: GrantCheck,
  ): Promise<AuthorizeDecision> {
    const startedAt = process.hrtime.bigint();
    const evaluation = grant.valid
      ? await this.evaluateFailClosed(
          tenantClient,
          tenantId,
          authenticatedAgentId,
          request,
          'GRANT_REDEMPTION',
        )
      : deny(grant.reason);
    return this.commit(
      tenantClient,
      tenantId,
      authenticatedAgentId,
      request,
      context,
      evaluation,
      {
        stage: 'GRANT_REDEMPTION',
        grantId: grant.valid ? grant.grantId : undefined,
      },
      startedAt,
    );
  }

  private async evaluateFailClosed(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    authenticatedAgentId: string,
    request: AuthorizeRequest,
    stage: DecisionStage,
    hostId?: string,
  ): Promise<Evaluation> {
    try {
      return await this.evaluate(
        tenantClient,
        tenantId,
        authenticatedAgentId,
        request,
        stage,
        hostId,
      );
    } catch (error) {
      if (error instanceof HttpException) throw error;
      this.logger.error(
        `authorize failed closed for task "${request.taskId}": ${error instanceof Error ? error.message : String(error)}`,
      );
      return deny(ENFORCEMENT_DEPENDENCY_UNAVAILABLE);
    }
  }

  /**
   * Writes the `Decision` row, then audits. For ALLOW the reservation (the
   * execution-count increment on a first attempt, the grant consumption on
   * redemption) and the insert are one transaction, so a decision that
   * commits has reserved its execution and one that does not commit has not.
   * Losing the reservation race turns ALLOW into DENY before anything is
   * written. Any failure here is a 503 (`failClosed`): the caller never gets
   * a decision it could execute under without a durable record of it.
   */
  private async commit(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    agentId: string,
    request: AuthorizeRequest,
    context: DecisionContext,
    evaluation: Evaluation,
    kind: DecisionRecordKind,
    startedAt: bigint,
  ): Promise<AuthorizeDecision> {
    try {
      const result = await this.commitAndAudit(
        tenantClient,
        tenantId,
        agentId,
        request,
        context,
        evaluation,
        kind,
      );
      recordDecision(
        startedAt,
        result.decision,
        'reason' in result ? result.reason : undefined,
      );
      return result;
    } catch (error) {
      // The decision could not be recorded: the caller gets a 503 and must
      // not act, so it counts against availability, never as an ALLOW.
      recordDecision(startedAt, 'ERROR', ENFORCEMENT_DEPENDENCY_UNAVAILABLE);
      throw error;
    }
  }

  private async commitAndAudit(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    agentId: string,
    request: AuthorizeRequest,
    context: DecisionContext,
    evaluation: Evaluation,
    kind: DecisionRecordKind,
  ): Promise<AuthorizeDecision> {
    const insert = (
      client: Pick<TenantPrismaClient, 'decision'>,
      final: Evaluation,
    ) => this.insertDecision(client, agentId, request, context, final, kind);

    const { decisionId, final } = await failClosed('decision-store', () => {
      if (evaluation.verdict.decision !== 'ALLOW') {
        return insert(tenantClient, evaluation);
      }
      const task = evaluation.task;
      return tenantClient.$transaction(async (tx) => {
        const reserved =
          kind.stage === 'GRANT_REDEMPTION'
            ? await this.consumeGrant(tx, kind.grantId)
            : task !== undefined &&
              (await this.tasksService.incrementExecutionCount(tx, task));
        return insert(
          tx,
          reserved
            ? evaluation
            : deny(
                kind.stage === 'GRANT_REDEMPTION'
                  ? 'grant_already_consumed'
                  : 'task_execution_limit_reached',
              ),
        );
      });
    });

    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType:
        final.verdict.decision === 'ALLOW'
          ? AUDIT_EVENT_TYPES.AUTHORIZATION_ALLOWED
          : final.verdict.decision === 'DENY'
            ? AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED
            : AUDIT_EVENT_TYPES.AUTHORIZATION_PENDING_APPROVAL,
      actor: { type: 'agent', id: agentId },
      data: {
        taskId: request.taskId,
        toolId: request.toolId,
        actionId: request.actionId,
        resource: request.resource,
        decisionId,
        channel: context.channel,
        stage: kind.stage,
        ...(kind.stage === 'GRANT_REDEMPTION' && kind.grantId
          ? { grantId: kind.grantId }
          : {}),
        ...('reason' in final.verdict ? { reason: final.verdict.reason } : {}),
        ...final.audit,
      },
    });
    const usedGrantId = final.audit['allowGrantId'];
    if (final.verdict.decision === 'ALLOW' && typeof usedGrantId === 'string') {
      await this.recordGrantUse(tenantClient, tenantId, agentId, usedGrantId, {
        decisionId,
        toolId: request.toolId,
        actionId: request.actionId,
        resource: request.resource,
        ...(context.hostId ? { hostId: context.hostId } : {}),
      });
    }
    return { ...final.verdict, decisionId };
  }

  /** `approval.grant.used`; a failure here is logged, never turned into a different decision. */
  private async recordGrantUse(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    agentId: string,
    grantId: string,
    data: Record<string, unknown>,
  ): Promise<void> {
    try {
      await markAllowGrantUsed(tenantClient, grantId);
    } catch (error) {
      this.logger.error(
        `could not count use of allow grant "${grantId}": ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.APPROVAL_GRANT_USED,
      actor: { type: 'agent', id: agentId },
      data: { grantId, ...data },
    });
  }

  /** Single use, enforced in the database: only one redemption can win. */
  private async consumeGrant(
    tx: Pick<TenantPrismaClient, 'authorizationGrant'>,
    grantId: string | undefined,
  ): Promise<boolean> {
    if (!grantId) return false;
    const now = new Date();
    const result = await tx.authorizationGrant.updateMany({
      where: {
        id: grantId,
        consumedAt: null,
        revokedAt: null,
        expiresAt: { gt: now },
      },
      data: { consumedAt: now },
    });
    return result.count > 0;
  }

  private async insertDecision(
    client: Pick<TenantPrismaClient, 'decision'>,
    agentId: string,
    request: AuthorizeRequest,
    context: DecisionContext,
    evaluation: Evaluation,
    kind: DecisionRecordKind,
  ): Promise<{ decisionId: string; final: Evaluation }> {
    const { verdict } = evaluation;
    const decisive = verdict.decision === 'ALLOW' ? 'allowed' : verdict.reason;
    const row = await client.decision.create({
      data: {
        outcome: verdict.decision,
        reasonCodes:
          verdict.decision === 'DENY'
            ? [decisive]
            : [decisive, ...(evaluation.riskReasonCodes ?? [])],
        policyId: evaluation.policyId ?? null,
        policyVersionId: evaluation.policyVersionId ?? null,
        riskScore:
          verdict.decision === 'DENY' ? null : (evaluation.riskScore ?? null),
        inputsHash: computeParameterHash({
          ...request,
          params: context.params,
        }),
        agentId,
        taskId: request.taskId,
        toolId: request.toolId,
        actionId: request.actionId,
        resource: request.resource,
        channel: context.channel,
        stage: kind.stage,
        grantId:
          kind.stage === 'GRANT_REDEMPTION' ? (kind.grantId ?? null) : null,
        correlationId: correlationIdForRecord(),
      },
    });
    return { decisionId: row.id, final: evaluation };
  }

  private async evaluate(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    authenticatedAgentId: string,
    request: AuthorizeRequest,
    stage: DecisionStage,
    hostId?: string,
  ): Promise<Evaluation> {
    const redemption = stage === 'GRANT_REDEMPTION';

    // Step 0 (kill-switch phase, Section 32): platform → tenant → agent →
    // agent-group(s) → tool, then AI-system lifecycle. Runs before the task
    // is even resolved — none of these checks need it, and this is the
    // cheapest, most fundamental "don't bother evaluating anything else"
    // gate in the whole pipeline. See KillSwitchService.checkAll's own doc
    // comment for the exact per-scope lookup order.
    const killSwitchCheck = await this.killSwitchService.checkAll(
      tenantClient,
      tenantId,
      { agentId: authenticatedAgentId, toolId: request.toolId },
    );
    if (killSwitchCheck.killed) {
      return deny(killSwitchCheck.reason as string, {
        killSwitchScope: killSwitchCheck.scope,
      });
    }

    let task: TaskRecord;
    try {
      task = await this.tasksService.getTaskOrThrow(
        tenantClient,
        request.taskId,
      );
    } catch (error) {
      if (error instanceof TaskNotFoundError) return deny('task_not_found');
      throw error;
    }

    // Step 1.
    if (task.assignedAgentId !== authenticatedAgentId) {
      return deny('not_assigned_agent', {
        assignedAgentId: task.assignedAgentId,
      });
    }

    // Steps 2-3: the full ancestor chain, then the task itself.
    const liveness = await this.tasksService.evaluateFullLiveness(
      tenantClient,
      tenantId,
      task,
      new Date(),
      { executionAlreadyCounted: redemption },
    );
    if (!liveness.ok) return deny(liveness.reason as string);

    // Step 3b: the tenant's catalog (src/platform/catalog.*). The watcher's built-in connector
    // needs the `watcher` feature and a pack-bound task needs its pack enabled by Manar staff.
    // A catalog read failure throws, and `evaluateFailClosed` denies with
    // `enforcement_dependency_unavailable`.
    const catalogDeny = await this.catalog.taskDenyReason(
      tenantId,
      task,
      request.toolId,
    );
    if (catalogDeny) return deny(catalogDeny);

    // Step 4.
    const forbidden = parseToolActions(task.forbiddenActions);
    const isForbidden = forbidden.some(
      (f) => f.toolId === request.toolId && f.actionId === request.actionId,
    );
    if (isForbidden) return deny('forbidden_action');

    // Step 5.
    const agentSubject = agentObjectId(tenantId, authenticatedAgentId);
    const exactGrant = grantObjectId(
      tenantId,
      task.id,
      request.toolId,
      request.actionId,
      request.resource,
    );
    const wildcardGrant = grantObjectId(
      tenantId,
      task.id,
      request.toolId,
      request.actionId,
      ANY_RESOURCE_PATTERN,
    );

    let exactAllowed = false;
    let wildcardAllowed = false;
    // Spec 7.2: redeeming an approved grant is the high-risk path; it bypasses the allow cache.
    const consistency = redemption ? ('high' as const) : undefined;
    try {
      [exactAllowed, wildcardAllowed] = await Promise.all([
        this.openFga.check(
          {
            user: agentSubject,
            relation: 'can_use',
            object: exactGrant,
          },
          { consistency },
        ),
        this.openFga.check(
          {
            user: agentSubject,
            relation: 'can_use',
            object: wildcardGrant,
          },
          { consistency },
        ),
      ]);
    } catch (error) {
      this.logger.error(
        `OpenFGA check failed for task "${task.id}" — failing closed (DENY)`,
        error instanceof Error ? error.stack : undefined,
      );
      return deny(ENFORCEMENT_DEPENDENCY_UNAVAILABLE);
    }
    const openFgaResult = { exactAllowed, wildcardAllowed };
    if (!exactAllowed && !wildcardAllowed) {
      return deny('not_authorized', { openFgaResult });
    }

    // Step 5b (spec 4.6): a live "Approve for 8 hours" grant for this device (or agent), tool,
    // action and exact resource. Looked up before policy evaluation, but it only satisfies an
    // approval requirement below: a policy DENY, a kill switch, OpenFGA and the task's limits are
    // all decided without it. A lookup failure throws and `evaluateFailClosed` denies.
    const allowGrant = redemption
      ? null
      : await findLiveAllowGrant(
          tenantClient,
          hostId ? { hostId } : { agentId: authenticatedAgentId },
          {
            toolId: request.toolId,
            actionId: request.actionId,
            resource: request.resource,
          },
        );

    // Step 6 (Phase 6): PolicyEngine — an extra, org-defined restriction
    // on top of the already-OpenFGA-permitted action above, never a
    // re-decision of it. See PolicyEngine's own doc comment for why "no
    // rule matched" (effect ALLOW, the common case) is never conflated
    // with "couldn't evaluate" (also effect DENY, but for a genuine
    // load/parse failure — logged there, not re-logged here).
    const policyResult = await this.policyEngine.evaluate(
      tenantClient,
      tenantId,
      {
        toolId: request.toolId,
        actionId: request.actionId,
        resource: request.resource,
      },
    );
    const policy = {
      policyId: policyResult.policyId,
      policyVersionId: policyResult.policyVersionId,
    };
    if (policyResult.effect === 'DENY') {
      return deny(
        policyResult.failureReason
          ? 'policy_evaluation_failed'
          : 'policy_denied',
        {
          matchedRule: policyResult.matchedRule ?? null,
          policyVersionId: policyResult.policyVersionId ?? null,
          policyFailureReason: policyResult.failureReason ?? null,
        },
        policy,
      );
    }

    // Redemption: a human approved this exact request, so the policy asking
    // for approval and the risk ceiling are already satisfied; only DENY
    // (above) refuses. The grant is consumed in `commit`.
    if (redemption) {
      return {
        verdict: { decision: 'ALLOW' },
        audit: {
          policyVersionId: policyResult.policyVersionId ?? null,
          matchedRule: policyResult.matchedRule ?? null,
          openFgaResult,
        },
        ...policy,
        task,
      };
    }

    // Step 7 (Phase 6): RiskEngine. finalRiskScore vs. this task's own
    // riskCeiling — either that or the matched policy rule itself asking
    // for approval routes this request to APPROVAL_REQUIRED instead of ALLOW.
    const riskResult = await this.riskEngine.score(tenantClient, {
      tenantId,
      toolId: request.toolId,
      actionId: request.actionId,
      resource: request.resource,
      task,
      agentId: authenticatedAgentId,
      policyMatch: policyResult.matchedRule,
    });
    const scored = {
      ...policy,
      riskScore: riskResult.riskScore,
      riskReasonCodes: riskResult.reasonCodes,
    };

    const needsApproval =
      policyResult.effect === 'APPROVAL_REQUIRED' ||
      riskResult.riskScore > task.riskCeiling;
    if (needsApproval && !allowGrant) {
      const reason =
        policyResult.effect === 'APPROVAL_REQUIRED'
          ? 'policy_requires_approval'
          : 'risk_ceiling_exceeded';
      return {
        verdict: {
          decision: 'APPROVAL_REQUIRED',
          reason,
          riskScore: riskResult.riskScore,
          policyVersionId: policyResult.policyVersionId ?? null,
          deterministicRiskScore: riskResult.riskScore,
          riskReasonCodes: riskResult.reasonCodes,
          riskCeiling: task.riskCeiling,
        },
        audit: {
          riskScore: riskResult.riskScore,
          riskReasonCodes: riskResult.reasonCodes,
          policyVersionId: policyResult.policyVersionId ?? null,
          matchedRule: policyResult.matchedRule ?? null,
          riskCeiling: task.riskCeiling,
        },
        ...scored,
      };
    }

    // Step 8: ALLOW (a live grant counts as the approval). The atomic, race-closing `executionCount` increment
    // (`TasksService.incrementExecutionCount`) happens in `commit`, in the
    // same transaction as the `Decision` insert.
    return {
      verdict: { decision: 'ALLOW' },
      audit: {
        riskScore: riskResult.riskScore,
        policyVersionId: policyResult.policyVersionId ?? null,
        matchedRule: policyResult.matchedRule ?? null,
        openFgaResult,
        ...(needsApproval && allowGrant ? { allowGrantId: allowGrant.id } : {}),
      },
      ...scored,
      task,
    };
  }
}
