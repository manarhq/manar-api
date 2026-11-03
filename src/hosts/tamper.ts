import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/**
 * What a device reports when something takes Manar's hook out of play (manar-edge
 * internal/protect/tamper.go). Personal mode cannot stop the person, or a program they run, from
 * doing that; the device blocks AI tools from it and says what it saw. Stored with the other
 * device events (`secret_events`), audited, and shown as "tampered" on the device.
 */
export const TAMPER_EVENT_TYPES = [
  /** A hook refused an AI tool's change to a hook or settings file. */
  'protect.tamper.settings_write',
  /** Manar's hook was taken out of a settings file it protects (the device put it back). */
  'protect.tamper.hook_removed',
  /** A project's Claude Code settings set disableAllHooks. */
  'protect.tamper.hooks_disabled',
  /** Claude Code was started with --settings. */
  'protect.tamper.settings_flag',
  /** Claude Code ran with CLAUDE_CONFIG_DIR away from ~/.claude. */
  'protect.tamper.config_dir',
] as const;
export type TamperEventType = (typeof TAMPER_EVENT_TYPES)[number];

/** A device is shown as tampered, and the tool's label is capped, this long after the last report. */
export const TAMPER_WINDOW_MS = 7 * 86_400_000;

export interface TamperInfo {
  at: string;
  kind: TamperEventType;
  toolId: string | null;
  maskedPath: string | null;
}

/** The latest tamper report within the window, per device. */
export async function latestTamper(
  client: TenantPrismaClient,
  hostIds: string[],
  now = Date.now(),
): Promise<Map<string, TamperInfo>> {
  if (hostIds.length === 0) return new Map();
  const rows = await client.secretEvent.findMany({
    where: {
      hostId: { in: hostIds },
      type: { in: [...TAMPER_EVENT_TYPES] },
      at: { gte: new Date(now - TAMPER_WINDOW_MS) },
    },
    orderBy: [{ at: 'desc' }, { id: 'desc' }],
    distinct: ['hostId'],
    select: {
      hostId: true,
      type: true,
      toolId: true,
      maskedPath: true,
      at: true,
    },
  });
  return new Map(
    rows.map((r) => [
      r.hostId,
      {
        at: r.at.toISOString(),
        kind: r.type as TamperEventType,
        toolId: r.toolId,
        maskedPath: r.maskedPath,
      },
    ]),
  );
}
