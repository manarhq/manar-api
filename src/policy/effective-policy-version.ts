import { createHash } from 'node:crypto';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { HOST_RISK_CEILING } from '../host-coverage/host-authorize.service';
import {
  HOST_CLAUDE_CODE_ACTIONS,
  HOST_GENERIC_ACTIONS,
  KNOWN_HOST_TOOL_IDS,
  hostActionRisk,
} from '../tools/host-actions';
import { PolicyContentSchema } from './policy-content.schema';

/**
 * Changes when a release changes how a host action is judged: the tool catalogue, every action's
 * risk and the risk ceiling. Part of the token below, so such a release wipes device caches.
 */
export const HOST_RULES_VERSION = createHash('sha256')
  .update(
    JSON.stringify({
      tools: KNOWN_HOST_TOOL_IDS,
      ceiling: HOST_RISK_CEILING,
      risk: KNOWN_HOST_TOOL_IDS.map((t) =>
        [...HOST_CLAUDE_CODE_ACTIONS, ...HOST_GENERIC_ACTIONS].map((a) => [
          t,
          a.name,
          hostActionRisk(t, a.name),
        ]),
      ),
    }),
  )
  .digest('hex')
  .slice(0, 8);

export interface HostPolicyState {
  /** Opaque token; the device only compares it. */
  version: string;
  /** A published rule for host tools and `read` that denies or asks: no folder rule offline. */
  restrictiveReadRule: boolean;
}

const isHostTool = (t: string) => t === '*' || KNOWN_HOST_TOOL_IDS.includes(t);

/**
 * What can turn a plain, cacheable ALLOW for this device into a DENY, as one opaque token: the
 * latest published version of every policy (the ids decisions stamp as `policyVersionId`), the
 * kill switches that reach this device (tenant, this host, host tools), the platform switch,
 * pause, the host's live BLOCK (revoked after use) entries, the host tools' registry
 * classification and risk, and HOST_RULES_VERSION. Unrelated switches do not change it. Also
 * reports whether a published read rule makes offline folder reads unsafe. Throws on a read
 * failure: the caller fails the poll, never answers with a stale or empty value.
 */
export async function hostPolicyState(
  client: TenantPrismaClient,
  hostId: string,
  platformKillSwitchActive: boolean,
  now: Date = new Date(),
): Promise<HostPolicyState> {
  const tools = await client.tool.findMany({
    where: { name: { in: [...KNOWN_HOST_TOOL_IDS] } },
    select: { id: true },
  });
  const toolIds = tools.map((t) => t.id);
  const [policies, switches, pause, blocks, actions] = await Promise.all([
    client.policyVersion.findMany({
      where: { status: 'PUBLISHED' },
      orderBy: [{ policyId: 'asc' }, { version: 'desc' }],
      distinct: ['policyId'],
      select: { id: true, content: true },
    }),
    client.killSwitch.findMany({
      where: {
        active: true,
        OR: [
          { scope: 'TENANT' },
          { scope: 'AGENT', targetId: hostId },
          { scope: 'TOOL', targetId: { in: toolIds } },
        ],
      },
      orderBy: { id: 'asc' },
      select: { id: true },
    }),
    client.workspacePause.findUnique({
      where: { id: 'workspace' },
      select: { paused: true },
    }),
    client.approvalAllowGrant.findMany({
      where: {
        hostId,
        effect: 'BLOCK',
        revokedAt: null,
        expiresAt: { gt: now },
      },
      orderBy: { id: 'asc' },
      select: { id: true },
    }),
    client.toolAction.findMany({
      where: { tool: { name: { in: [...KNOWN_HOST_TOOL_IDS] } } },
      orderBy: { id: 'asc' },
      select: { id: true, classification: true, riskBaseScore: true },
    }),
  ]);
  const parts = {
    policies: policies.map((p) => p.id).sort(),
    switches: switches.map((r) => r.id),
    platform: platformKillSwitchActive,
    paused: pause?.paused === true,
    blocks: blocks.map((r) => r.id),
    actions: actions.map(
      (r) => `${r.id}:${r.classification}:${r.riskBaseScore}`,
    ),
    rules: HOST_RULES_VERSION,
  };
  const restrictiveReadRule = policies.some((p) => {
    const parsed = PolicyContentSchema.safeParse(p.content);
    // Unreadable content is treated as restrictive (fail closed).
    if (!parsed.success) return true;
    return parsed.data.rules.some(
      (r) =>
        isHostTool(r.toolId) &&
        (r.actionId === '*' || r.actionId.toLowerCase() === 'read') &&
        r.effect !== 'ALLOW',
    );
  });
  return {
    version: createHash('sha256')
      .update(JSON.stringify(parts))
      .digest('hex')
      .slice(0, 16),
    restrictiveReadRule,
  };
}
