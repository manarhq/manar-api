import { ForbiddenException, Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import type { AgentContext } from '../agent-mtls/agent-context';
import { TenantDatabaseManager } from '../database/tenant-database-manager.service';
import { KillSwitchService } from '../kill-switches/kill-switch.service';
import { TasksService } from '../tasks/tasks.service';
import type { TaskRecord } from '../tasks/tasks.service';
import { TaskNotFoundError } from '../tasks/tasks.errors';
import { failClosed } from '../common/fail-closed/fail-closed';
import { CatalogService } from '../platform/catalog.service';

export interface TaskAccess {
  tenantClient: TenantPrismaClient;
  task: TaskRecord;
  /** Tools the tenant's catalog keeps out of the manifest (the watcher's connector when off). */
  hiddenTools: string[];
}

/** 403 in the same shape `POST /agent/v1/tools/invoke` uses for a DENY. */
export function denied(reason: string): ForbiddenException {
  return new ForbiddenException({ decision: 'DENY', reason });
}

/**
 * The gate in front of every task-scoped agent-runtime endpoint (LLM proxy,
 * tool manifest, MCP server; ADR-0002): kill switches (platform, tenant,
 * agent, agent group, AI system), then the task exists, is assigned to the
 * mTLS-authenticated agent, and it and every ancestor is ACTIVE, inside its
 * time window and under its execution limit, and, for a pack-bound task, its pack is enabled. The same checks and reason
 * codes as steps 0-3 of `AuthorizationService`, reusing the same services.
 *
 * DENY -> 403 `{ decision: 'DENY', reason }`. Any store failure -> 503
 * `enforcement_dependency_unavailable`.
 */
@Injectable()
export class AgentTaskAccessService {
  constructor(
    private readonly tenantDatabaseManager: TenantDatabaseManager,
    private readonly killSwitchService: KillSwitchService,
    private readonly tasksService: TasksService,
    private readonly catalog: CatalogService,
  ) {}

  async assertTaskAccess(
    agent: AgentContext,
    taskId: string,
  ): Promise<TaskAccess> {
    const tenantClient = await failClosed('tenant-db', () =>
      this.tenantDatabaseManager.getClient(agent.tenant.id),
    );

    const killSwitch = await failClosed('kill-switch-store', () =>
      this.killSwitchService.checkAll(tenantClient, agent.tenant.id, {
        agentId: agent.agent.id,
      }),
    );
    if (killSwitch.killed) {
      throw denied(killSwitch.reason ?? 'kill_switch_active');
    }

    const task = await failClosed('tenant-db', async () => {
      try {
        return await this.tasksService.getTaskOrThrow(tenantClient, taskId);
      } catch (error) {
        if (error instanceof TaskNotFoundError) throw denied('task_not_found');
        throw error;
      }
    });
    if (task.assignedAgentId !== agent.agent.id) {
      throw denied('not_assigned_agent');
    }

    const liveness = await failClosed('tenant-db', () =>
      this.tasksService.evaluateFullLiveness(
        tenantClient,
        agent.tenant.id,
        task,
        new Date(),
      ),
    );
    if (!liveness.ok) throw denied(liveness.reason ?? 'task_not_live');

    // A pack-bound task stops when staff disable its pack (src/platform/catalog.*).
    const catalogDeny = await failClosed('catalog-store', () =>
      this.catalog.taskDenyReason(agent.tenant.id, task),
    );
    if (catalogDeny) throw denied(catalogDeny);
    const hiddenTools = await failClosed('catalog-store', () =>
      this.catalog.hiddenTools(agent.tenant.id),
    );

    return { tenantClient, task, hiddenTools };
  }
}
