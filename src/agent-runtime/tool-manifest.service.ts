import { Injectable } from '@nestjs/common';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { deserializeTriple } from '../authorization/grant-triples';
import { TasksService } from '../tasks/tasks.service';
import type { TaskRecord } from '../tasks/tasks.service';
import { failClosed } from '../common/fail-closed/fail-closed';

/** Separator between toolId and actionId in a manifest tool name. Split on the FIRST occurrence. */
export const TOOL_NAME_SEPARATOR = '__';

export interface ManifestTool {
  /** `<toolId>__<actionId>` */
  name: string;
  toolId: string;
  actionId: string;
  description: string;
  inputSchema: unknown;
  mutating: boolean;
  destructive: boolean;
  /** Every resource pattern the effective grant set allows for this action; `"*"` means any resource. */
  resourceSelector: string[];
}

export interface ToolManifest {
  taskId: string;
  tools: ManifestTool[];
}

export function toolName(toolId: string, actionId: string): string {
  return `${toolId}${TOOL_NAME_SEPARATOR}${actionId}`;
}

export function parseToolName(
  name: string,
): { toolId: string; actionId: string } | null {
  const at = name.indexOf(TOOL_NAME_SEPARATOR);
  if (at <= 0) return null;
  const actionId = name.slice(at + TOOL_NAME_SEPARATOR.length);
  return actionId ? { toolId: name.slice(0, at), actionId } : null;
}

/**
 * The per-task tool manifest (Addendum 01 §C.3): the task's EFFECTIVE grant
 * set (own allowed actions minus forbidden, intersected with every
 * ancestor's), restricted to registered actions of enabled tools. What the
 * model sees is exactly what the capability allows; listing a tool here is
 * not an authorization, every call still runs the full pipeline.
 */
@Injectable()
export class ToolManifestService {
  constructor(private readonly tasksService: TasksService) {}

  async build(
    tenantClient: TenantPrismaClient,
    task: TaskRecord,
    /** Tool names the tenant's catalog switched off (listing is not authorization either way). */
    hiddenTools: string[] = [],
  ): Promise<ToolManifest> {
    return failClosed('tenant-db', async () => {
      const effective = await this.tasksService.getEffectiveGrantSet(
        tenantClient,
        task,
      );
      const patterns = new Map<string, Set<string>>();
      for (const serialized of effective) {
        const triple = deserializeTriple(serialized);
        const key = toolName(triple.toolId, triple.actionId);
        const set = patterns.get(key) ?? new Set<string>();
        set.add(triple.pattern);
        patterns.set(key, set);
      }

      const toolIds = [
        ...new Set([...patterns.keys()].map((k) => parseToolName(k)!.toolId)),
      ].filter((id) => !hiddenTools.includes(id));
      const tools = await tenantClient.tool.findMany({
        where: { name: { in: toolIds }, enabled: true },
        include: { actions: true },
      });

      const manifest: ManifestTool[] = [];
      for (const tool of tools) {
        for (const action of tool.actions) {
          const name = toolName(tool.name, action.name);
          const allowed = patterns.get(name);
          if (!allowed) continue;
          manifest.push({
            name,
            toolId: tool.name,
            actionId: action.name,
            description: action.description ?? '',
            inputSchema: action.inputSchema ?? { type: 'object' },
            mutating: action.mutating,
            destructive: action.destructive,
            resourceSelector: [...allowed].sort(),
          });
        }
      }
      manifest.sort((a, b) => a.name.localeCompare(b.name));
      return { taskId: task.id, tools: manifest };
    });
  }
}
