import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AgentsService } from '../agents/agents.service';
import {
  computeGrantSet,
  deserializeTriple,
  isSubset,
} from '../authorization/grant-triples';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { AuditService } from '../audit/audit.service';
import {
  DEFAULT_RISK_CEILING,
  TaskRecord,
  TasksService,
} from '../tasks/tasks.service';
import { TaskNotFoundError } from '../tasks/tasks.errors';
import type { DelegateTaskRequest } from './delegation.validation';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { failClosed } from '../common/fail-closed/fail-closed';
import {
  DelegationDeniedError,
  DelegationExceedsParentAuthorityError,
  DelegationExceedsParentLimitsError,
  DelegationNotAssignedAgentError,
  DelegationTaskNotLiveError,
} from './delegation.errors';

/** Levels of delegation below a human-created task (its children are level 1). */
export const MAX_DELEGATION_DEPTH = 3;
/** Child tasks one task may ever delegate, revoked ones included. */
export const MAX_DELEGATIONS_PER_TASK = 5;

export interface DelegationResult {
  childTask: TaskRecord;
  childAgent: { id: string; slug: string; identifier: string };
  enrollmentToken: { token: string; expiresAt: Date };
}

/**
 * `POST /agent/v1/tasks/:id/delegate` (Section 20). A child task can never
 * exceed its parent's *effective* authority — enforced by a single
 * deterministic subset check (`DelegationService.delegate`'s step 4)
 * performed entirely before any write, so a rejected delegation leaves
 * *nothing* persisted: no child Agent, no child Task, no OpenFGA tuples
 * (verified by the privilege-amplification/exceeds-parent-authority e2e
 * tests — see test/task-delegation.e2e-spec.ts).
 *
 * Reuses Phase 4's real enrollment mechanism unchanged (`AgentsService`) —
 * the child agent gets its own independent certificate via the same
 * one-time `AgentEnrollmentToken` flow a human-created agent uses, not a
 * new identity mechanism. The chain Human → Parent Task → Parent Agent →
 * Child Task → Child Agent stays reconstructable via `Task.parentTaskId` +
 * `Task.assignedAgentId` + `Agent.createdBy` — both the child Task's
 * `requesterId` and the child Agent's `createdBy` are set to the *root*
 * task's original human requester (resolved by walking the ancestor
 * chain), never the delegating agent, since an agent has no `UserProfile`
 * row (see Task.requesterId's schema doc comment).
 */
@Injectable()
export class DelegationService {
  private readonly logger = new Logger(DelegationService.name);

  constructor(
    private readonly tasksService: TasksService,
    private readonly agentsService: AgentsService,
    private readonly auditService: AuditService,
    private readonly killSwitchService: KillSwitchService,
  ) {}

  async delegate(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    tenantSlug: string,
    parentTaskId: string,
    callerAgentId: string,
    input: DelegateTaskRequest,
  ): Promise<DelegationResult> {
    // ADR-0009: a stopped agent (quarantined, killed, its AI system
    // suspended) cannot mint a fresh child agent to act through. Fails
    // closed (503) if the state cannot be read.
    const stopped = await failClosed('kill-switch-store', () =>
      this.killSwitchService.checkAll(tenantClient, tenantId, {
        agentId: callerAgentId,
      }),
    );
    if (stopped.killed) {
      throw new DelegationDeniedError(stopped.reason ?? 'kill_switch_active');
    }

    const parentTask = await this.tasksService.getTaskOrThrow(
      tenantClient,
      parentTaskId,
    );

    // Caller must be the task's assigned agent -- permission flows
    // through the task, never attached to the agent directly.
    if (parentTask.assignedAgentId !== callerAgentId) {
      throw new DelegationNotAssignedAgentError(parentTaskId);
    }

    // A task that isn't itself fully live (including every one of ITS
    // ancestors) cannot hand out any of its authority either -- this is
    // slightly stricter than the bare letter of the design spec, which
    // only requires the *grant* subset check below, but is clearly within
    // its spirit: Section 20's non-amplification invariant would be
    // meaningless if a revoked/expired task could still mint fresh
    // sub-tasks.
    const liveness = await failClosed('tenant-db', () =>
      this.tasksService.evaluateFullLiveness(
        tenantClient,
        tenantId,
        parentTask,
        new Date(),
      ),
    );
    if (!liveness.ok) {
      throw new DelegationTaskNotLiveError(
        parentTaskId,
        liveness.reason as string,
      );
    }

    // Bounded fan-out: executions and the LLM token budget are shared with
    // the root task, but every child is a new agent with its own rate
    // limit, so the tree itself is capped too.
    const ancestors = await failClosed('tenant-db', () =>
      this.tasksService.getAncestorChain(tenantClient, parentTask),
    );
    if (ancestors.length + 1 > MAX_DELEGATION_DEPTH) {
      throw new DelegationDeniedError('delegation_depth_exceeded');
    }
    if (
      (await this.countChildren(tenantClient, parentTask.id)) >=
      MAX_DELEGATIONS_PER_TASK
    ) {
      throw new DelegationDeniedError('delegation_limit_reached');
    }

    // Deterministic subset check (step 1 of the design spec's Delegation
    // section): the requested child grant set must already be within the
    // parent's *effective* grant set -- itself already narrowed by every
    // ancestor's own grants (TasksService.getEffectiveGrantSet), not just
    // the parent's raw stored allowedToolActions/allowedResourceSelectors.
    const parentEffectiveGrants = await this.tasksService.getEffectiveGrantSet(
      tenantClient,
      parentTask,
    );
    const requestedGrants = computeGrantSet(
      input.allowedToolActions,
      input.allowedResourceSelectors,
      input.forbiddenActions,
    );
    if (!isSubset(requestedGrants, parentEffectiveGrants)) {
      const rejected = [...requestedGrants]
        .filter((triple) => !parentEffectiveGrants.has(triple))
        .map(deserializeTriple);
      throw new DelegationExceedsParentAuthorityError(rejected);
    }

    // Same non-amplification rule for the task's limits (Gate 0 R3): a
    // child never gets a higher riskCeiling than the parent, nor more
    // executions than the parent has left. An explicit request for more is
    // rejected like a broader grant; an omitted value is clamped. The
    // liveness check above guarantees parentRemaining >= 1. Only the direct
    // parent is compared: it was itself clamped against its own parent when
    // delegated. Every child execution also counts on the parent and each
    // ancestor (TasksService.incrementExecutionCount), so the budget is shared.
    const parentRemaining =
      parentTask.maxExecutions == null
        ? null
        : parentTask.maxExecutions - parentTask.executionCount;
    if (
      input.riskCeiling !== undefined &&
      input.riskCeiling > parentTask.riskCeiling
    ) {
      throw new DelegationExceedsParentLimitsError(
        `Requested riskCeiling ${input.riskCeiling} exceeds the parent task's ${parentTask.riskCeiling}`,
      );
    }
    if (
      parentRemaining !== null &&
      input.maxExecutions !== undefined &&
      (input.maxExecutions === null || input.maxExecutions > parentRemaining)
    ) {
      throw new DelegationExceedsParentLimitsError(
        `Requested maxExecutions ${input.maxExecutions ?? 'unlimited'} exceeds the parent task's ${parentRemaining} remaining`,
      );
    }
    const riskCeiling =
      input.riskCeiling ??
      Math.min(parentTask.riskCeiling, DEFAULT_RISK_CEILING);
    const maxExecutions =
      input.maxExecutions === undefined ? parentRemaining : input.maxExecutions;

    // Everything below this line only runs once the subset check has
    // already passed -- no partial writes are possible on rejection.
    const rootRequesterId = await this.tasksService.resolveRootRequesterId(
      tenantClient,
      parentTask,
    );

    const childAgent = await this.agentsService.createAgent(tenantClient, {
      slug: input.childAgentSlug,
      displayName:
        input.childAgentDisplayName ??
        `Delegated agent "${input.childAgentSlug}"`,
      tenantSlug,
      createdBy: rootRequesterId,
    });

    const enrollmentToken = await this.agentsService.createEnrollmentToken(
      tenantClient,
      childAgent.id,
      tenantSlug,
      rootRequesterId,
    );

    // Never lets a child outlive its parent, even though the ancestor
    // walk at authorize-time would already deny it regardless -- pure
    // hygiene (a shorter, more honest expiresAt), not a security
    // boundary in itself.
    const expiresAt =
      input.expiresAt &&
      input.expiresAt.getTime() < parentTask.expiresAt.getTime()
        ? input.expiresAt
        : parentTask.expiresAt;

    const childTask = await this.tasksService.createTask(
      tenantClient,
      tenantId,
      {
        name: input.name,
        description: input.description ?? null,
        requesterId: rootRequesterId,
        assignedAgentId: childAgent.id,
        parentTaskId: parentTask.id,
        allowedToolActions: input.allowedToolActions,
        allowedResourceSelectors: input.allowedResourceSelectors,
        forbiddenActions: input.forbiddenActions,
        expiresAt,
        maxExecutions,
        riskCeiling,
        // A child of a pack-bound task stays bound to the same pack.
        packId: parentTask.packId ?? null,
        // The delegating agent, not the root human requester — see
        // CreateTaskInput.actor's doc comment.
        actor: { type: 'agent', id: callerAgentId },
      },
    );

    // Concurrent requests can all pass the count above; the late ones are
    // revoked here before anyone learns their ids.
    if (
      (await this.countChildren(tenantClient, parentTask.id)) >
      MAX_DELEGATIONS_PER_TASK
    ) {
      await tenantClient.task.update({
        where: { id: childTask.id },
        data: { status: 'REVOKED' },
      });
      throw new DelegationDeniedError('delegation_limit_reached');
    }

    this.logger.log(
      `Task "${parentTaskId}" delegated to new agent "${childAgent.identifier}" (child task "${childTask.id}")`,
    );

    await this.auditService.recordSafely(tenantClient, tenantId, {
      eventType: AUDIT_EVENT_TYPES.TASK_DELEGATED,
      actor: { type: 'agent', id: callerAgentId },
      data: {
        parentTaskId: parentTask.id,
        childTaskId: childTask.id,
        childAgentId: childAgent.id,
        childAgentIdentifier: childAgent.identifier,
        allowedToolActions: input.allowedToolActions,
        allowedResourceSelectors: input.allowedResourceSelectors,
        forbiddenActions: input.forbiddenActions,
        expiresAt: childTask.expiresAt,
        maxExecutions: childTask.maxExecutions,
        riskCeiling: childTask.riskCeiling,
      },
    });

    return {
      childTask,
      childAgent: {
        id: childAgent.id,
        slug: childAgent.slug,
        identifier: childAgent.identifier,
      },
      enrollmentToken: {
        token: enrollmentToken.rawToken,
        expiresAt: enrollmentToken.expiresAt,
      },
    };
  }

  private countChildren(
    tenantClient: TenantPrismaClient,
    parentTaskId: string,
  ): Promise<number> {
    return failClosed('tenant-db', () =>
      tenantClient.task.count({ where: { parentTaskId } }),
    );
  }
}

/** Re-exported for the controller's error-mapping convenience — a delegation target that doesn't resolve to any task at all is just `TaskNotFoundError` (`TasksService.getTaskOrThrow` already throws it). */
export { TaskNotFoundError };
