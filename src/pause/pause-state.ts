import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/** The reason every protect and hook path gives while a workspace is paused. */
export const PAUSED_REASON = 'paused';

/** True while the workspace's "Pause all AI" is on. A read error propagates (callers fail closed). */
export async function isWorkspacePaused(
  client: Pick<TenantPrismaClient, 'workspacePause'>,
): Promise<boolean> {
  const row = await client.workspacePause.findUnique({
    where: { id: 'workspace' },
    select: { paused: true },
  });
  return row?.paused === true;
}
