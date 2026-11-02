import { hostTool } from '../tools/host-actions';

/**
 * The console's "Am I protected?" answer. It makes the same checks as `manar-edge status` on the
 * device (enrolled and approved, service checking in, last sync, each AI tool protected, modules
 * running), from what the devices reported here, so the console and the device agree. Problems
 * are codes, not sentences: the console words them in English and Arabic and picks the fix.
 */

/** Modules every current device runs; one missing from a device that reports modules is a problem. */
export const EXPECTED_MODULES = [
  'discovery',
  'protect',
  'warden',
  'jail',
  'door',
  'secrets-watch',
] as const;

export type ProtectionProblemCode =
  /** No device is enrolled (`manar-edge status`: not connected to Manar). */
  | 'no_device'
  /** The device waits for approval. */
  | 'device_pending'
  /** Approved but has never checked in. */
  | 'device_never_synced'
  /** Approved but has not checked in for longer than the stale window. */
  | 'device_offline'
  /** The owner turned protection off for this tool. */
  | 'tool_off'
  /** Protection is wanted, the device could not apply it. */
  | 'tool_not_applied'
  /** Manar can see this tool but has no way to control it. */
  | 'tool_seen_only'
  /** A module of the device service stopped and is restarting. */
  | 'module_down'
  /** A module this version should run did not report. */
  | 'module_missing';

export interface ProtectionProblem {
  code: ProtectionProblemCode;
  hostId?: string;
  hostname?: string;
  toolId?: string;
  toolName?: string;
  module?: string;
  lastSeenAt?: string | null;
}

export interface ProtectionDevice {
  hostId: string;
  hostname: string;
  os: string;
  status: string;
  online: boolean;
  lastSeenAt: string | null;
  toolsProtected: number;
  toolsTotal: number;
}

export interface ProtectionStatus {
  ok: boolean;
  checkedAt: string;
  devices: ProtectionDevice[];
  problems: ProtectionProblem[];
}

export interface ProtectionHostRow {
  id: string;
  hostname: string;
  os: string;
  status: string;
  lastSeenAt: Date | null;
  modules: unknown;
  tools: Array<{
    toolId: string;
    name: string;
    protected: boolean;
    desiredProtection: boolean;
  }>;
}

type ModuleState = { state?: unknown; detail?: unknown };

export function protectionStatus(
  hosts: ProtectionHostRow[],
  now: Date,
  staleMs: number,
): ProtectionStatus {
  const problems: ProtectionProblem[] = [];
  const devices: ProtectionDevice[] = [];
  if (hosts.length === 0) problems.push({ code: 'no_device' });
  for (const h of hosts) {
    const where = { hostId: h.id, hostname: h.hostname };
    const lastSeenAt = h.lastSeenAt?.toISOString() ?? null;
    const online =
      !!h.lastSeenAt && now.getTime() - h.lastSeenAt.getTime() <= staleMs;
    devices.push({
      hostId: h.id,
      hostname: h.hostname,
      os: h.os,
      status: h.status,
      online,
      lastSeenAt,
      toolsProtected: h.tools.filter((t) => t.protected).length,
      toolsTotal: h.tools.length,
    });
    if (h.status === 'PENDING') {
      problems.push({ code: 'device_pending', ...where });
      continue;
    }
    if (h.status !== 'APPROVED') continue;
    if (!h.lastSeenAt) {
      problems.push({ code: 'device_never_synced', ...where });
      continue;
    }
    // Like the device, never judge tools or modules from stale data.
    if (!online) {
      problems.push({ code: 'device_offline', ...where, lastSeenAt });
      continue;
    }
    for (const t of h.tools) {
      if (t.protected) continue;
      const code: ProtectionProblemCode =
        (hostTool(t.toolId)?.modes.length ?? 0) === 0
          ? 'tool_seen_only'
          : t.desiredProtection
            ? 'tool_not_applied'
            : 'tool_off';
      problems.push({ code, ...where, toolId: t.toolId, toolName: t.name });
    }
    const modules =
      h.modules && typeof h.modules === 'object' && !Array.isArray(h.modules)
        ? (h.modules as Record<string, ModuleState>)
        : null;
    // An older device reports no modules: unknown, not a problem.
    if (!modules) continue;
    for (const [name, m] of Object.entries(modules).sort(([a], [b]) =>
      a.localeCompare(b),
    )) {
      if (m?.state === 'problem')
        problems.push({ code: 'module_down', ...where, module: name });
    }
    for (const name of EXPECTED_MODULES) {
      if (!(name in modules))
        problems.push({ code: 'module_missing', ...where, module: name });
    }
  }
  return {
    ok: problems.length === 0,
    checkedAt: now.toISOString(),
    devices,
    problems,
  };
}
