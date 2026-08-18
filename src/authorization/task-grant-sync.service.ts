import { Injectable, Logger } from '@nestjs/common';
import {
  ResourceSelector,
  ToolAction,
  computeGrantSet,
  deserializeTriple,
} from './grant-triples';
import {
  agentObjectId,
  grantObjectId,
  resourceObjectId,
  taskObjectId,
  toolActionObjectId,
  toolObjectId,
} from './openfga-object-id.util';
import { OpenFgaClientService, TupleKey } from './openfga-client.service';

export interface TaskGrantInput {
  taskId: string;
  assignedAgentId: string;
  allowedToolActions: readonly ToolAction[];
  allowedResourceSelectors: readonly ResourceSelector[];
  forbiddenActions: readonly ToolAction[];
}

/**
 * Mirrors a Task's Postgres JSON columns (`allowedToolActions`,
 * `allowedResourceSelectors`, `forbiddenActions`) into OpenFGA relationship
 * tuples — the two are meant to represent the exact same decision from two
 * angles (audit-readable vs. enforcement substrate — see
 * docs/authorization-model.md), so this service writes a straightforward,
 * unfiltered 1:1 tuple-ization of those three columns rather than any
 * derived/"effective" subset: the "explicit deny wins" *logic* lives
 * identically in both places (`AuthorizationService`'s app-layer
 * short-circuit AND the model's own `but not forbidden_agent` exclusion),
 * not just in one or the other.
 *
 * Called once, at task-creation time (root task creation and delegation
 * both funnel through `TasksService.createTask`/`createChildTask`, which
 * calls this after the Task row is committed) — tasks are immutable after
 * creation this phase (no "update task" endpoint), so there is no update/
 * resync path to build yet.
 */
@Injectable()
export class TaskGrantSyncService {
  private readonly logger = new Logger(TaskGrantSyncService.name);

  constructor(private readonly openFga: OpenFgaClientService) {}

  async writeTaskGrants(
    tenantId: string,
    input: TaskGrantInput,
  ): Promise<void> {
    const tuples = new Map<string, TupleKey>();
    const addTuple = (tuple: TupleKey) => {
      tuples.set(`${tuple.user}|${tuple.relation}|${tuple.object}`, tuple);
    };

    const task = taskObjectId(tenantId, input.taskId);
    const agent = agentObjectId(tenantId, input.assignedAgentId);
    addTuple({ user: agent, relation: 'assigned_agent', object: task });

    // The full, unfiltered allow set -- every {toolId, actionId} x
    // {toolId, pattern} pairing, regardless of forbiddenActions (see class
    // doc comment for why the exclusion is applied via OpenFGA's `but not`
    // instead of by omitting tuples here).
    const allowedSet = computeGrantSet(
      input.allowedToolActions,
      input.allowedResourceSelectors,
    );
    for (const serialized of allowedSet) {
      const { toolId, actionId, pattern } = deserializeTriple(serialized);
      this.addGrantGraph(
        addTuple,
        tenantId,
        task,
        input.taskId,
        toolId,
        actionId,
        pattern,
      );
    }

    // forbiddenActions crossed with the same resource selectors -- mirrors
    // exactly which grant object(s) a {toolId, actionId} deny applies to.
    // A forbidden pair with no matching resource selector produces nothing
    // (there is no grant object to attach forbidden_agent to), same as an
    // allowed pair with no matching selector grants nothing.
    const forbiddenSet = computeGrantSet(
      input.forbiddenActions,
      input.allowedResourceSelectors,
    );
    for (const serialized of forbiddenSet) {
      const { toolId, actionId, pattern } = deserializeTriple(serialized);
      this.addGrantGraph(
        addTuple,
        tenantId,
        task,
        input.taskId,
        toolId,
        actionId,
        pattern,
      );
      const grant = grantObjectId(
        tenantId,
        input.taskId,
        toolId,
        actionId,
        pattern,
      );
      addTuple({ user: agent, relation: 'forbidden_agent', object: grant });
    }

    const writes = [...tuples.values()];
    if (writes.length === 0) return;

    this.logger.log(
      `Writing ${writes.length} OpenFGA tuple(s) for task "${input.taskId}"`,
    );
    await this.openFga.write({ writes });
  }

  /** Writes the supporting relationship graph (tool_action->tool, resource->tool, grant->{of_task,tool_action,resource}) for one grant triple — idempotent via `addTuple`'s de-duplicating Map. */
  private addGrantGraph(
    addTuple: (tuple: TupleKey) => void,
    tenantId: string,
    task: string,
    taskId: string,
    toolId: string,
    actionId: string,
    pattern: string,
  ): void {
    const tool = toolObjectId(tenantId, toolId);
    const toolAction = toolActionObjectId(tenantId, toolId, actionId);
    const resource = resourceObjectId(tenantId, toolId, pattern);
    const grant = grantObjectId(tenantId, taskId, toolId, actionId, pattern);

    addTuple({ user: tool, relation: 'tool', object: toolAction });
    addTuple({ user: tool, relation: 'tool', object: resource });
    addTuple({ user: task, relation: 'of_task', object: grant });
    addTuple({ user: toolAction, relation: 'tool_action', object: grant });
    addTuple({ user: resource, relation: 'resource', object: grant });
  }
}
