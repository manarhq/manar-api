import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AgentsService } from '../agents/agents.service';
import {
  computeGrantSet,
  deserializeTriple,
  isSubset,
} from '../authorization/grant-triples';
import { TaskRecord, TasksService } from '../tasks/tasks.service';
import { TaskNotFoundError } from '../tasks/tasks.errors';
import type { DelegateTaskRequest } from './delegation.validation';
import {
  DelegationExceedsParentAuthorityError,
  DelegationNotAssignedAgentError,
  DelegationTaskNotLiveError,
} from './delegation.errors';

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
  ) {}

  async delegate(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    tenantSlug: string,
    parentTaskId: string,
    callerAgentId: string,
    input: DelegateTaskRequest,
  ): Promise<DelegationResult> {
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
    const liveness = await this.tasksService.evaluateFullLiveness(
      tenantClient,
      parentTask,
      new Date(),
    );
    if (!liveness.ok) {
      throw new DelegationTaskNotLiveError(
        parentTaskId,
        liveness.reason as string,
      );
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
        maxExecutions: input.maxExecutions,
        riskCeiling: input.riskCeiling,
      },
    );

    this.logger.log(
      `Task "${parentTaskId}" delegated to new agent "${childAgent.identifier}" (child task "${childTask.id}")`,
    );

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
}

/** Re-exported for the controller's error-mapping convenience — a delegation target that doesn't resolve to any task at all is just `TaskNotFoundError` (`TasksService.getTaskOrThrow` already throws it). */
export { TaskNotFoundError };
