import { describe, expect, it, vi } from 'vitest';
import { serializeTriple } from '../authorization/grant-triples';
import type { TaskRecord } from '../tasks/tasks.service';
import { ToolManifestService } from './tool-manifest.service';

/** The tenant catalog can keep a tool out of the manifest (the watcher's connector when off). */
describe('ToolManifestService hidden tools', () => {
  const tool = (name: string, action: string) => ({
    name,
    actions: [
      {
        name: action,
        description: '',
        inputSchema: { type: 'object' },
        mutating: false,
        destructive: false,
      },
    ],
  });
  const build = (hidden?: string[]) => {
    const findMany = vi.fn(({ where }: { where: { name: { in: string[] } } }) =>
      Promise.resolve(
        [
          tool('graph', 'entra.user.get'),
          tool('manar', 'manar.activity.read'),
        ].filter((t) => where.name.in.includes(t.name)),
      ),
    );
    const service = new ToolManifestService({
      getEffectiveGrantSet: () =>
        Promise.resolve(
          new Set([
            serializeTriple({
              toolId: 'graph',
              actionId: 'entra.user.get',
              pattern: '*',
            }),
            serializeTriple({
              toolId: 'manar',
              actionId: 'manar.activity.read',
              pattern: '*',
            }),
          ]),
        ),
    } as never);
    return service.build(
      { tool: { findMany } } as never,
      { id: 'task-1' } as TaskRecord,
      hidden,
    );
  };

  it('lists every granted tool by default', async () => {
    const m = await build();
    expect(m.tools.map((t) => t.toolId).sort()).toEqual(['graph', 'manar']);
  });

  it('leaves out the tools the catalog hides', async () => {
    const m = await build(['manar']);
    expect(m.tools.map((t) => t.toolId)).toEqual(['graph']);
  });
});
