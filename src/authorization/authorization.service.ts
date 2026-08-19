import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import { TaskNotFoundError } from '../tasks/tasks.errors';
import { PolicyEngine } from '../policy/policy-engine.service';
import { RiskEngine } from '../risk/risk-engine.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import type { AuditEventType } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { parseToolActions } from './grant-triples';
import {
  ANY_RESOURCE_PATTERN,
  agentObjectId,
  grantObjectId,
} from './openfga-object-id.util';
import { OpenFgaClientService } from './openfga-client.service';
import type { AuthorizeRequest } from './authorize-request.validation';

export type AuthorizeDecision =
  | { decision: 'ALLOW' }
  | { decision: 'DENY'; reason: string }
  | {
      decision: 'REQUIRE_APPROVAL';
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
    };

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
 *      `REQUIRE_APPROVAL` if the matched policy's own effect says so, OR
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
 * (network failure, wrong port, container down) is caught and treated as
 * DENY too (`authorization_backend_unavailable`) — never as ALLOW, and
 * never as an unhandled 5xx that could be mistaken for anything but a
 * definite non-ALLOW. Steps 6-7 (Phase 6) are inserted strictly *after*
 * Phase 5's own OpenFGA check and *before* its `executionCount` increment
 * — none of Phase 5's steps 1-5 are touched. `REQUIRE_APPROVAL` is a real,
 * stable decision from this phase onward, but this phase implements no
 * path to ever fulfil one (Phase 8) — it's correctly a dead end for now.
 * See docs/policy-model.md.
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
  ) {}

  async authorize(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    authenticatedAgentId: string,
    request: AuthorizeRequest,
  ): Promise<AuthorizeDecision> {
    // Phase 9a: every branch below records an `authorization.allowed`/
    // `authorization.denied`/`authorization.pending_approval` AuditEvent
    // before returning — via `this.audit(...)`, a thin wrapper so each
    // branch stays a single `return` statement while still carrying
    // "enough data to reconstruct why" (Section 46: matched policy, risk
    // score, OpenFGA result) in `data`. Never changes what's returned to
    // the caller — `auditService.recordSafely` never throws.
    const audit = (
      eventType: AuditEventType,
      data: Record<string, unknown>,
    ): Promise<unknown> =>
      this.auditService.recordSafely(tenantClient, tenantId, {
        eventType,
        actor: { type: 'agent', id: authenticatedAgentId },
        data: {
          taskId: request.taskId,
          toolId: request.toolId,
          actionId: request.actionId,
          resource: request.resource,
          ...data,
        },
      });

    // Step 0 (kill-switch phase, Section 32): platform → tenant → agent →
    // agent-group(s) → tool. Runs before the task is even resolved — none
    // of these five checks need it, and this is the cheapest, most
    // fundamental "don't bother evaluating anything else" gate in the
    // whole pipeline. See KillSwitchService.checkAll's own doc comment for
    // the exact per-scope lookup order.
    const killSwitchCheck = await this.killSwitchService.checkAll(
      tenantClient,
      tenantId,
      { agentId: authenticatedAgentId, toolId: request.toolId },
    );
    if (killSwitchCheck.killed) {
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
        reason: killSwitchCheck.reason,
        killSwitchScope: killSwitchCheck.scope,
      });
      return { decision: 'DENY', reason: killSwitchCheck.reason as string };
    }

    let task: TaskRecord;
    try {
      task = await this.tasksService.getTaskOrThrow(
        tenantClient,
        request.taskId,
      );
    } catch (error) {
      if (error instanceof TaskNotFoundError) {
        await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
          reason: 'task_not_found',
        });
        return { decision: 'DENY', reason: 'task_not_found' };
      }
      throw error;
    }

    // Step 1.
    if (task.assignedAgentId !== authenticatedAgentId) {
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
        reason: 'not_assigned_agent',
        assignedAgentId: task.assignedAgentId,
      });
      return { decision: 'DENY', reason: 'not_assigned_agent' };
    }

    const now = new Date();

    // Steps 2-3: the full ancestor chain, then the task itself.
    const liveness = await this.tasksService.evaluateFullLiveness(
      tenantClient,
      task,
      now,
    );
    if (!liveness.ok) {
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
        reason: liveness.reason,
      });
      return { decision: 'DENY', reason: liveness.reason as string };
    }

    // Step 4.
    const forbidden = parseToolActions(task.forbiddenActions);
    const isForbidden = forbidden.some(
      (f) => f.toolId === request.toolId && f.actionId === request.actionId,
    );
    if (isForbidden) {
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
        reason: 'forbidden_action',
      });
      return { decision: 'DENY', reason: 'forbidden_action' };
    }

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

    let allowed: boolean;
    let exactAllowed = false;
    let wildcardAllowed = false;
    try {
      [exactAllowed, wildcardAllowed] = await Promise.all([
        this.openFga.check({
          user: agentSubject,
          relation: 'can_use',
          object: exactGrant,
        }),
        this.openFga.check({
          user: agentSubject,
          relation: 'can_use',
          object: wildcardGrant,
        }),
      ]);
      allowed = exactAllowed || wildcardAllowed;
    } catch (error) {
      this.logger.error(
        `OpenFGA check failed for task "${task.id}" — failing closed (DENY)`,
        error instanceof Error ? error.stack : undefined,
      );
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
        reason: 'authorization_backend_unavailable',
      });
      return { decision: 'DENY', reason: 'authorization_backend_unavailable' };
    }

    if (!allowed) {
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
        reason: 'not_authorized',
        openFgaResult: { exactAllowed, wildcardAllowed },
      });
      return { decision: 'DENY', reason: 'not_authorized' };
    }

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
    if (policyResult.effect === 'DENY') {
      const reason = policyResult.failureReason
        ? 'policy_evaluation_failed'
        : 'policy_denied';
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
        reason,
        matchedRule: policyResult.matchedRule ?? null,
        policyVersionId: policyResult.policyVersionId ?? null,
        policyFailureReason: policyResult.failureReason ?? null,
      });
      return { decision: 'DENY', reason };
    }

    // Step 7 (Phase 6): RiskEngine. finalRiskScore vs. this task's own
    // riskCeiling (Phase 5's field, unused until now) — either that or
    // the matched policy rule itself asking for approval routes this
    // request to REQUIRE_APPROVAL instead of ALLOW.
    const riskResult = await this.riskEngine.score(tenantClient, {
      tenantId,
      toolId: request.toolId,
      actionId: request.actionId,
      resource: request.resource,
      task,
      agentId: authenticatedAgentId,
      policyMatch: policyResult.matchedRule,
    });

    if (
      policyResult.effect === 'REQUIRE_APPROVAL' ||
      riskResult.finalRiskScore > task.riskCeiling
    ) {
      const reason =
        policyResult.effect === 'REQUIRE_APPROVAL'
          ? 'policy_requires_approval'
          : 'risk_ceiling_exceeded';
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_PENDING_APPROVAL, {
        reason,
        riskScore: riskResult.finalRiskScore,
        riskReasonCodes: riskResult.reasonCodes,
        policyVersionId: policyResult.policyVersionId ?? null,
        matchedRule: policyResult.matchedRule ?? null,
        riskCeiling: task.riskCeiling,
      });
      return {
        decision: 'REQUIRE_APPROVAL',
        reason,
        riskScore: riskResult.finalRiskScore,
        policyVersionId: policyResult.policyVersionId ?? null,
      };
    }

    // Step 8 (was Phase 5's step 6). `TasksService.incrementExecutionCount`
    // (Phase 8 hoisted this atomic, race-closing increment out of this
    // class and into `TasksService` — the same single-conditional-update
    // pattern `AgentsService.enroll` uses for single-use enrollment tokens
    // — since `GrantService`, Phase 8, needs to perform this exact same
    // increment once for an approved action, at grant-issuance time; one
    // implementation, not two copies that could drift).
    const incremented = await this.tasksService.incrementExecutionCount(
      tenantClient,
      task,
    );
    if (!incremented) {
      await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED, {
        reason: 'task_execution_limit_reached',
      });
      return { decision: 'DENY', reason: 'task_execution_limit_reached' };
    }

    await audit(AUDIT_EVENT_TYPES.AUTHORIZATION_ALLOWED, {
      riskScore: riskResult.finalRiskScore,
      policyVersionId: policyResult.policyVersionId ?? null,
      matchedRule: policyResult.matchedRule ?? null,
      openFgaResult: { exactAllowed, wildcardAllowed },
    });
    return { decision: 'ALLOW' };
  }
}
