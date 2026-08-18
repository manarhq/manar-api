import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import { TaskNotFoundError } from '../tasks/tasks.errors';
import { parseToolActions } from './grant-triples';
import {
  ANY_RESOURCE_PATTERN,
  agentObjectId,
  grantObjectId,
} from './openfga-object-id.util';
import { OpenFgaClientService } from './openfga-client.service';
import type { AuthorizeRequest } from './authorize-request.validation';

export type AuthorizeDecision =
  { decision: 'ALLOW' } | { decision: 'DENY'; reason: string };

/**
 * `POST /agent/v1/authorize`'s pipeline (Section 22 — fail-closed at every
 * step; if any check can't be evaluated trustworthily, DENY). Implements
 * the design spec's 6 steps exactly:
 *
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
 *   6. On ALLOW, atomically increment `executionCount` — a conditional
 *      `UPDATE` that also closes the race against a concurrent request
 *      exhausting `maxExecutions` between step 3's read and this write.
 *
 * Steps 1-4 return a specific, non-leaky reason (deterministic app-layer
 * state, safe to expose). Step 5's DENY is deliberately generic
 * (`not_authorized`) — never surfacing *why* OpenFGA denied, so a caller
 * can't probe the shape of the authorization model. An OpenFGA outage
 * (network failure, wrong port, container down) is caught and treated as
 * DENY too (`authorization_backend_unavailable`) — never as ALLOW, and
 * never as an unhandled 5xx that could be mistaken for anything but a
 * definite non-ALLOW.
 */
@Injectable()
export class AuthorizationService {
  private readonly logger = new Logger(AuthorizationService.name);

  constructor(
    private readonly tasksService: TasksService,
    private readonly openFga: OpenFgaClientService,
  ) {}

  async authorize(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    authenticatedAgentId: string,
    request: AuthorizeRequest,
  ): Promise<AuthorizeDecision> {
    let task: TaskRecord;
    try {
      task = await this.tasksService.getTaskOrThrow(
        tenantClient,
        request.taskId,
      );
    } catch (error) {
      if (error instanceof TaskNotFoundError) {
        return { decision: 'DENY', reason: 'task_not_found' };
      }
      throw error;
    }

    // Step 1.
    if (task.assignedAgentId !== authenticatedAgentId) {
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
      return { decision: 'DENY', reason: liveness.reason as string };
    }

    // Step 4.
    const forbidden = parseToolActions(task.forbiddenActions);
    const isForbidden = forbidden.some(
      (f) => f.toolId === request.toolId && f.actionId === request.actionId,
    );
    if (isForbidden) {
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
    try {
      const [exactAllowed, wildcardAllowed] = await Promise.all([
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
      return { decision: 'DENY', reason: 'authorization_backend_unavailable' };
    }

    if (!allowed) {
      return { decision: 'DENY', reason: 'not_authorized' };
    }

    // Step 6.
    const incremented = await this.incrementExecutionCount(tenantClient, task);
    if (!incremented) {
      return { decision: 'DENY', reason: 'task_execution_limit_reached' };
    }

    return { decision: 'ALLOW' };
  }

  /**
   * Atomically increments `executionCount`, guarded by `maxExecutions`
   * when set (a conditional `UPDATE ... WHERE executionCount < maxExecutions`
   * — the same single-conditional-update race-closing pattern
   * `AgentsService.enroll` uses for single-use enrollment tokens). Returns
   * `false` if a concurrent request already exhausted the limit between
   * step 3's read and this write.
   */
  private async incrementExecutionCount(
    tenantClient: TenantPrismaClient,
    task: TaskRecord,
  ): Promise<boolean> {
    if (task.maxExecutions == null) {
      await tenantClient.task.update({
        where: { id: task.id },
        data: { executionCount: { increment: 1 } },
      });
      return true;
    }

    const result = await tenantClient.task.updateMany({
      where: { id: task.id, executionCount: { lt: task.maxExecutions } },
      data: { executionCount: { increment: 1 } },
    });
    return result.count > 0;
  }
}
