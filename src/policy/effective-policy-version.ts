import { createHash } from 'node:crypto';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';

/**
 * An opaque token for everything that can turn a plain, cacheable ALLOW for this device into a
 * DENY: the published policy versions (the ids decisions stamp as `policyVersionId`), every active
 * kill switch (tenant, agent, group, tool) and the platform switch, pause, the host's quarantine,
 * group memberships and AI-system lifecycle, the host's live BLOCK (revoked after use) entries, and
 * the tool registry classification and risk. It changes when any of them changes, carries no
 * content, and the device only compares it. Throws on a read failure: the caller must fail the
 * poll, never answer with a stale or empty value.
 */
export async function effectivePolicyVersion(
  client: TenantPrismaClient,
  hostId: string,
  platformKillSwitchActive: boolean,
  now: Date = new Date(),
): Promise<string> {
  const [
    policies,
    switches,
    pause,
    quarantine,
    memberships,
    links,
    blocks,
    actions,
  ] = await Promise.all([
    client.policyVersion.findMany({
      where: { status: 'PUBLISHED' },
      orderBy: [{ policyId: 'asc' }, { version: 'desc' }],
      select: { id: true, policyId: true },
    }),
    client.killSwitch.findMany({
      where: { active: true },
      orderBy: { id: 'asc' },
      select: { id: true },
    }),
    client.workspacePause.findUnique({
      where: { id: 'workspace' },
      select: { paused: true },
    }),
    client.agentQuarantine.findFirst({
      where: { agentId: hostId, active: true },
      select: { id: true },
    }),
    client.agentGroupMembership.findMany({
      where: { agentId: hostId },
      orderBy: { groupId: 'asc' },
      select: { groupId: true },
    }),
    client.aiSystemAgentLink.findMany({
      where: { agentId: hostId },
      select: { aiSystemId: true },
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
      orderBy: { id: 'asc' },
      select: { id: true, classification: true, riskBaseScore: true },
    }),
  ]);
  const systems = links.length
    ? await client.aiSystem.findMany({
        where: { id: { in: links.map((l) => l.aiSystemId) } },
        orderBy: { id: 'asc' },
        select: { id: true, lifecycleState: true },
      })
    : [];
  const latest = new Map<string, string>();
  for (const r of policies)
    if (!latest.has(r.policyId)) latest.set(r.policyId, r.id);
  const parts = {
    policies: [...latest.values()].sort(),
    switches: switches.map((r) => r.id),
    platform: platformKillSwitchActive,
    paused: pause?.paused === true,
    quarantined: quarantine !== null,
    groups: memberships.map((r) => r.groupId),
    systems: systems.map((r) => `${r.id}:${r.lifecycleState}`),
    blocks: blocks.map((r) => r.id),
    actions: actions.map(
      (r) => `${r.id}:${r.classification}:${r.riskBaseScore}`,
    ),
  };
  return createHash('sha256')
    .update(JSON.stringify(parts))
    .digest('hex')
    .slice(0, 16);
}
