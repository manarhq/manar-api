import { isIP } from 'node:net';
import { normalizeEgressHost } from '../edge/edge-net';

/** The prompt kind for a new site: a `HostApproval` with this action (no new table, brief section 3). */
export const SITE_CONNECT_ACTION = 'site.connect';

/**
 * Tools whose processes the device filters (Linux; Windows only behind `MANAR_JAIL_WINDOWS`). The
 * IDE agents and desktop apps are not filtered at launch: their own backends need many hosts.
 */
export const JAIL_TOOL_IDS = [
  'host.claude-code',
  'host.codex-cli',
  'host.gemini-cli',
  'host.copilot-cli',
] as const;

export const JAIL_TOOL_NAMES: Record<string, string> = {
  'host.claude-code': 'Claude Code',
  'host.codex-cli': 'Codex CLI',
  'host.gemini-cli': 'Gemini CLI',
  'host.copilot-cli': 'Copilot CLI',
};

export function isJailTool(toolId: string): boolean {
  return (JAIL_TOOL_IDS as readonly string[]).includes(toolId);
}

const LABEL = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/;

/**
 * What the device may ask about: a DNS name (also single-label and internal names, they are real
 * destinations on a laptop) or an IP literal. Lower case, no port, no wildcard. Null otherwise.
 */
export function normalizeAskedSite(input: string): string | null {
  const s = input.trim().toLowerCase().replace(/\.$/, '');
  if (s.length === 0 || s.length > 253) return null;
  if (isIP(s)) return s;
  return s.split('.').every((l) => LABEL.test(l)) ? s : null;
}

/**
 * What a person may type in the console: everything an ask can be, plus `*.suffix` for a public
 * name (never a whole public suffix such as `*.co.uk`).
 */
export function normalizeRuleSite(input: string): string | null {
  const s = input.trim().toLowerCase();
  if (s.startsWith('*.')) return normalizeEgressHost(s);
  return normalizeAskedSite(s);
}

export type SiteMode = 'ALLOW' | 'DENY';

export interface SiteRuleView {
  id: string;
  toolId: string;
  site: string;
  mode: SiteMode;
  expiresAt: Date | null;
}

/** True when the rule is still in force at `now`. */
export function ruleLive(r: { expiresAt: Date | null }, now: Date): boolean {
  return r.expiresAt === null || r.expiresAt > now;
}

/** `MANAR_JAIL_ENABLED` (default on) and `MANAR_JAIL_WINDOWS` (default off). */
export function jailFlags(env: NodeJS.ProcessEnv = process.env): {
  enabled: boolean;
  windows: boolean;
} {
  return {
    enabled: env.MANAR_JAIL_ENABLED !== 'false',
    windows: env.MANAR_JAIL_WINDOWS === 'true',
  };
}

/** Exact site, or `*.suffix` covering one label or more in front of the suffix (never the suffix itself). */
export function siteCovers(rule: string, site: string): boolean {
  if (rule === site) return true;
  return rule.startsWith('*.') && site.endsWith(rule.slice(1));
}
