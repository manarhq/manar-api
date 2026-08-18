import { Injectable, Logger } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import {
  ResourceSelector,
  ToolAction,
  computeGrantSet,
  intersectGrantSets,
  parseResourceSelectors,
  parseToolActions,
} from '../authorization/grant-triples';
import { TaskGrantSyncService } from '../authorization/task-grant-sync.service';
import { AncestorChainTooDeepError, TaskNotFoundError } from './tasks.errors';

/**
 * The subset of a Task row this module actually operates on — deliberately
 * a narrow structural shape rather than importing Prisma's generated
 * `Task` model type, matching this codebase's existing convention of
 * accepting minimal shapes at service boundaries (see
 * `certificate-authority.service.ts`'s `issueCertificate(agent: { id,
 * identifier })`). Every real call site is a genuine tenant-client query
 * result, which satisfies this structurally.
 */
export interface TaskRecord {
  id: string;
  parentTaskId: string | null;
  requesterId: string;
  assignedAgentId: string;
  status: string;
  startsAt: Date;
  expiresAt: Date;
  maxExecutions: number | null;
  executionCount: number;
  allowedToolActions: unknown;
  allowedResourceSelectors: unknown;
  forbiddenActions: unknown;
}

export interface CreateTaskInput {
  name: string;
  description?: string | null;
  requesterId: string;
  assignedAgentId: string;
  parentTaskId?: string | null;
  allowedToolActions: ToolAction[];
  allowedResourceSelectors: ResourceSelector[];
  forbiddenActions: ToolAction[];
  startsAt?: Date;
  expiresAt: Date;
  maxExecutions?: number | null;
  riskCeiling?: number;
}

export interface LivenessResult {
  ok: boolean;
  /** Present only when `ok` is false — a specific, non-leaky reason (this is app-layer deterministic state, never an OpenFGA decision, so there's nothing to avoid leaking — see AuthorizationService). */
  reason?: string;
}

/** A bound on ancestor-chain depth (see AncestorChainTooDeepError) — comfortably deeper than any legitimate delegation chain this phase's product surface could produce, while still catching a cyclic parentTaskId in finite time. */
const MAX_ANCESTOR_DEPTH = 64;

/**
 * Business logic for `Task` rows: creation (root and delegated child alike
 * — both funnel through `createTask`), the ancestor-chain walk Section
 * 20's real-time revocation-cascade enforcement depends on, and the
 * grant-set arithmetic (`getOwnGrantSet`/`getEffectiveGrantSet`) both the
 * authorize pipeline and the delegation subset check share. No controller
 * here — see `TasksHttpModule` (human-facing `/tasks`) and
 * `src/delegation/` (agent-facing `/agent/v1/tasks/:id/delegate`), both of
 * which depend on this module for its provider only.
 */
@Injectable()
export class TasksService {
  private readonly logger = new Logger(TasksService.name);

  constructor(private readonly grantSync: TaskGrantSyncService) {}

  /**
   * Creates a Task row (root when `input.parentTaskId` is unset, a
   * delegated child otherwise) and immediately mirrors its grants into
   * OpenFGA (`TaskGrantSyncService`) — the two writes happen inside the
   * same call so a caller never observes a Task row whose OpenFGA tuples
   * haven't been written yet. If the OpenFGA write fails after the
   * Postgres row is committed, the task is left ACTIVE but with no
   * enforceable grants (every OpenFGA check for it will DENY, fail-closed
   * — never silently permissive), consistent with this codebase's
   * established "no automatic rollback, fail loud" stance elsewhere (e.g.
   * `TenantDatabaseManager.provisionTenant`).
   */
  async createTask(
    tenantClient: TenantPrismaClient,
    tenantId: string,
    input: CreateTaskInput,
  ): Promise<TaskRecord> {
    const task = await tenantClient.task.create({
      data: {
        name: input.name,
        description: input.description ?? null,
        requesterId: input.requesterId,
        assignedAgentId: input.assignedAgentId,
        parentTaskId: input.parentTaskId ?? null,
        allowedToolActions: input.allowedToolActions,
        allowedResourceSelectors: input.allowedResourceSelectors,
        forbiddenActions: input.forbiddenActions,
        startsAt: input.startsAt ?? new Date(),
        expiresAt: input.expiresAt,
        maxExecutions: input.maxExecutions ?? null,
        riskCeiling: input.riskCeiling ?? 20,
      },
    });

    if (input.parentTaskId) {
      await tenantClient.taskDelegation.create({
        data: { parentTaskId: input.parentTaskId, childTaskId: task.id },
      });
    }

    await this.grantSync.writeTaskGrants(tenantId, {
      taskId: task.id,
      assignedAgentId: task.assignedAgentId,
      allowedToolActions: input.allowedToolActions,
      allowedResourceSelectors: input.allowedResourceSelectors,
      forbiddenActions: input.forbiddenActions,
    });

    return task;
  }

  async getTaskOrThrow(
    tenantClient: TenantPrismaClient,
    taskId: string,
  ): Promise<TaskRecord> {
    const task = await tenantClient.task.findUnique({ where: { id: taskId } });
    if (!task) throw new TaskNotFoundError(taskId);
    return task;
  }

  async revokeTask(
    tenantClient: TenantPrismaClient,
    taskId: string,
    reason: string,
  ): Promise<void> {
    const task = await this.getTaskOrThrow(tenantClient, taskId);
    await tenantClient.task.update({
      where: { id: task.id },
      data: { status: 'REVOKED' },
    });
    // No Task.revocationReason column (the design spec's Task schema
    // doesn't include one — kept minimal, matching it exactly); this is
    // this phase's "structured logs only" audit trail for the revoke
    // action itself (full audit hash-chaining is Phase 9's scope).
    this.logger.log(`Task "${task.id}" revoked: ${reason}`);
  }

  /**
   * Walks `parentTaskId` upward, returning every ancestor from the
   * immediate parent to the root — the task itself is NOT included.
   * Bounded (`MAX_ANCESTOR_DEPTH`) and fails closed
   * (`AncestorChainTooDeepError`) rather than looping forever on a cyclic
   * chain, which the schema doesn't otherwise prevent.
   */
  async getAncestorChain(
    tenantClient: TenantPrismaClient,
    task: TaskRecord,
  ): Promise<TaskRecord[]> {
    const ancestors: TaskRecord[] = [];
    let currentParentId = task.parentTaskId;
    let hops = 0;

    while (currentParentId) {
      hops += 1;
      if (hops > MAX_ANCESTOR_DEPTH) {
        throw new AncestorChainTooDeepError(task.id, MAX_ANCESTOR_DEPTH);
      }
      const parent = await tenantClient.task.findUnique({
        where: { id: currentParentId },
      });
      if (!parent) {
        // A parentTaskId pointing nowhere is data corruption -- fail
        // closed rather than silently treating the chain as ending here.
        throw new TaskNotFoundError(currentParentId);
      }
      ancestors.push(parent);
      currentParentId = parent.parentTaskId;
    }

    return ancestors;
  }

  /** Walks the ancestor chain to the root task and returns ITS requesterId — see Task.requesterId's schema doc comment for why every task in a delegation chain traces back to the same originating human. */
  async resolveRootRequesterId(
    tenantClient: TenantPrismaClient,
    task: TaskRecord,
  ): Promise<string> {
    const ancestors = await this.getAncestorChain(tenantClient, task);
    const root = ancestors.at(-1) ?? task;
    return root.requesterId;
  }

  /**
   * `{ ok: false, reason }` if `task` is not usable right now: not ACTIVE,
   * outside its `[startsAt, expiresAt]` window, or at/over
   * `maxExecutions`. Applied to both a task itself (authorize pipeline
   * step 3) and to every ancestor (step 2) — the same three checks either
   * way, just at a different position in the chain.
   */
  evaluateLiveness(task: TaskRecord, now: Date): LivenessResult {
    if (task.status !== 'ACTIVE') {
      return { ok: false, reason: `task_status_${task.status.toLowerCase()}` };
    }
    if (now < task.startsAt || now > task.expiresAt) {
      return { ok: false, reason: 'task_outside_time_window' };
    }
    if (
      task.maxExecutions != null &&
      task.executionCount >= task.maxExecutions
    ) {
      return { ok: false, reason: 'task_execution_limit_reached' };
    }
    return { ok: true };
  }

  /**
   * Combines `evaluateLiveness` across the *entire* chain: every ancestor
   * (Section 20's real-time revocation-cascade check) and then `task`
   * itself. Shared by `AuthorizationService` (steps 2-3 of the authorize
   * pipeline) and `DelegationService` (a delegating agent's own task must
   * be fully live before it may hand out any authority at all) — one
   * implementation, not two copies that could drift.
   */
  async evaluateFullLiveness(
    tenantClient: TenantPrismaClient,
    task: TaskRecord,
    now: Date,
  ): Promise<LivenessResult> {
    const ancestors = await this.getAncestorChain(tenantClient, task);
    for (const ancestor of ancestors) {
      const liveness = this.evaluateLiveness(ancestor, now);
      if (!liveness.ok) {
        return { ok: false, reason: `ancestor_${liveness.reason}` };
      }
    }
    return this.evaluateLiveness(task, now);
  }

  /** `task`'s own grant set — its `allowedToolActions` x `allowedResourceSelectors`, minus anything in its own `forbiddenActions`. Does NOT account for ancestors — see `getEffectiveGrantSet` for that. */
  getOwnGrantSet(task: TaskRecord): Set<string> {
    return computeGrantSet(
      parseToolActions(task.allowedToolActions),
      parseResourceSelectors(task.allowedResourceSelectors),
      parseToolActions(task.forbiddenActions),
    );
  }

  /**
   * A task's *effective* authority: its own grant set intersected with
   * every ancestor's own grant set, all the way to the root (Section 20 —
   * a task whose own authority was already narrowed by an ancestor can
   * never hand out more than what actually still applies to it). This is
   * what the delegation subset check compares a delegation request
   * against — never just the immediate parent's raw stored grants.
   */
  async getEffectiveGrantSet(
    tenantClient: TenantPrismaClient,
    task: TaskRecord,
  ): Promise<Set<string>> {
    const ancestors = await this.getAncestorChain(tenantClient, task);
    let effective = this.getOwnGrantSet(task);
    for (const ancestor of ancestors) {
      effective = intersectGrantSets(effective, this.getOwnGrantSet(ancestor));
    }
    return effective;
  }
}
