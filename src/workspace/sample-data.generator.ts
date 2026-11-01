import { createHash } from 'node:crypto';
import type { PrismaClient as TenantPrismaClient } from '../generated/tenant-client/client';
import { AuditService } from '../audit/audit.service';
import type { RecordAuditEventInput } from '../audit/audit.service';
import { AUDIT_EVENT_TYPES } from '../audit/audit-event-types';
import { HOST_TOOL_ENDPOINT } from '../tools/host-actions';

const DAY = 86_400_000;
/** Same shape as the mockup: 1,412 actions, 9 asked, 3 blocked, 2 secrets kept safe. */
const DAY_WEIGHTS = [40, 62, 55, 80, 92, 35, 58];
const ASKED_PER_DAY = [1, 2, 1, 1, 2, 0, 2]; // 9
const BLOCKED_PER_DAY = [0, 1, 0, 0, 1, 0, 1]; // 3
export const SAMPLE_TOTALS = {
  actions: 1412,
  askedYou: 9,
  blocked: 3,
  secretsKeptSafe: 2,
};

const TOOLS = [
  { id: 'host.claude-code', vendor: 'Claude Code' },
  { id: 'host.cursor', vendor: 'Cursor' },
  { id: 'host.codex-cli', vendor: 'Codex CLI' },
  { id: 'host.vscode-copilot', vendor: 'VS Code Copilot' },
  { id: 'host.windsurf', vendor: 'Windsurf' },
] as const;
const DEVICES = [
  {
    machineId: 'sample-win11-laptop',
    hostname: 'work-laptop',
    os: 'Windows 11',
  },
  {
    machineId: 'sample-ubuntu-desktop',
    hostname: 'home-desktop',
    os: 'Ubuntu 24.04',
  },
] as const;
const ACTIONS = ['read', 'edit', 'write', 'grep', 'bash'] as const;

/** 9 approvals: [tool index, action, resource, outcome]. The last one is waiting. */
const APPROVALS: [number, string, string, 'APPROVED' | 'DENIED' | 'PENDING'][] =
  [
    [0, 'bash', 'rm -rf dist', 'APPROVED'],
    [0, 'bash', 'git push --force origin feature', 'DENIED'],
    [2, 'bash', 'curl https://example.com/setup.sh', 'APPROVED'],
    [1, 'read', '~/notes/keys.txt', 'APPROVED'],
    [3, 'bash', 'rm -rf node_modules', 'APPROVED'],
    [0, 'bash', 'git push --force-with-lease', 'APPROVED'],
    [2, 'bash', 'wget https://example.com/tool.tar.gz', 'DENIED'],
    [4, 'bash', 'rm old-report.csv', 'APPROVED'],
    [1, 'read', '~/.aws/credentials', 'PENDING'],
  ];

/** Small deterministic PRNG so every sample workspace looks the same. */
function prng(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Actions per day (oldest first) summing to `total`. */
export function actionsPerDay(total: number): number[] {
  const sum = DAY_WEIGHTS.reduce((a, b) => a + b, 0);
  const days = DAY_WEIGHTS.map((w) => Math.floor((w / sum) * total));
  days[6]! += total - days.reduce((a, b) => a + b, 0);
  return days;
}

/**
 * Fills ONE tenant database (the SAMPLE workspace's) with synthetic data. Everything is written
 * through `client`, which the caller resolves for the sample tenant id and nothing else; the
 * generator never sees another tenant. One transaction: all of it or none.
 */
export async function generateSampleData(
  client: TenantPrismaClient,
  audit: AuditService,
  tenantId: string,
  ownerSubject: string,
  now: Date = new Date(),
): Promise<void> {
  const rand = prng(1412);
  const publish: Array<() => void> = [];
  await client.$transaction(
    async (tx) => {
      const owner = await tx.userProfile.upsert({
        where: { keycloakSubject: ownerSubject },
        create: {
          keycloakSubject: ownerSubject,
          email: 'you@sample.invalid',
          displayName: 'You',
        },
        update: {},
      });
      const group = await tx.hostGroup.create({ data: { name: 'Sample' } });
      for (const d of DEVICES) {
        await tx.host.create({
          data: {
            hostGroupId: group.id,
            ...d,
            keyType: 'SOFTWARE',
            status: 'APPROVED',
            approvedBy: owner.id,
            approvedAt: new Date(now.getTime() - 8 * DAY),
            lastSeenAt: new Date(now.getTime() - 60_000),
            registeredFromIp: '203.0.113.10',
            keyFingerprint: createHash('sha256')
              .update(d.machineId)
              .digest('hex'),
          },
        });
      }
      const agentIds: string[] = [];
      const taskIds: string[] = [];
      for (const t of TOOLS) {
        const tool = await tx.tool.create({
          data: {
            name: t.id,
            type: 'HOST',
            vendor: t.vendor,
            description: 'Sample tool',
            baseEndpoint: HOST_TOOL_ENDPOINT,
            protocol: 'HTTP',
            credentialReference: {
              provider: 'ENV',
              reference: 'MANAR_CONNECTOR_NONE',
            },
            enabled: false,
            metadata: { dataOrigin: 'SAMPLE' },
          },
        });
        await tx.toolAction.createMany({
          data: ACTIONS.map((name) => ({
            toolId: tool.id,
            name,
            riskBaseScore: name === 'bash' ? 20 : 5,
            mutating: name !== 'read' && name !== 'grep',
            destructive: name === 'bash',
          })),
        });
        const slug = t.id.replace('host.', 'sample-');
        const agent = await tx.agent.create({
          data: {
            slug,
            identifier: `agent://sample/${slug}`,
            displayName: t.vendor,
            status: 'ACTIVE',
            createdBy: owner.id,
          },
        });
        const task = await tx.task.create({
          data: {
            name: `${t.vendor} on this device`,
            requesterId: owner.id,
            assignedAgentId: agent.id,
            expiresAt: new Date(now.getTime() + 30 * DAY),
          },
        });
        agentIds.push(agent.id);
        taskIds.push(task.id);
      }

      const dayStart = (i: number) => now.getTime() - (7 - i) * DAY;
      const approvalAt = (i: number) => new Date(dayStart(i) + 0.4 * DAY);
      for (const [n, [ti, action, resource, status]] of APPROVALS.entries()) {
        const requestedAt =
          status === 'PENDING'
            ? new Date(now.getTime() - 20 * 60_000)
            : approvalAt(Math.min(6, Math.floor(n * 0.75)));
        const req = await tx.approvalRequest.create({
          data: {
            taskId: taskIds[ti]!,
            agentId: agentIds[ti]!,
            toolId: TOOLS[ti]!.id,
            actionId: action,
            resource,
            params: {},
            riskScore: 45,
            status,
            requestedAt,
            expiresAt: new Date(requestedAt.getTime() + 30 * 60_000),
            temporalWorkflowId: `sample-approval-${tenantId}-${n}`,
          },
        });
        if (status !== 'PENDING') {
          await tx.approvalDecision.create({
            data: {
              approvalRequestId: req.id,
              approverId: owner.id,
              decision: status === 'APPROVED' ? 'APPROVE' : 'DENY',
              decidedAt: new Date(requestedAt.getTime() + 90_000),
            },
          });
        }
      }

      // Seven days of audit history, back-dated, in the sample tenant's own chain.
      const events: RecordAuditEventInput[] = [];
      const at = (day: number, frac: number) =>
        new Date(Math.min(now.getTime() - 1000, dayStart(day) + frac * DAY));
      const decision = (
        type: string,
        day: number,
        frac: number,
        ti: number,
        action: string,
        resource: string,
      ) =>
        events.push({
          eventType: type as RecordAuditEventInput['eventType'],
          actor: { type: 'agent', id: agentIds[ti]! },
          timestamp: at(day, frac),
          data: {
            toolId: TOOLS[ti]!.id,
            actionId: action,
            resource,
            sample: true,
          },
        });
      const perDay = actionsPerDay(SAMPLE_TOTALS.actions);
      for (let d = 0; d < 7; d++) {
        const special = ASKED_PER_DAY[d]! + BLOCKED_PER_DAY[d]!;
        for (let i = 0; i < perDay[d]! - special; i++) {
          const ti = Math.floor(rand() * TOOLS.length);
          const a = ACTIONS[Math.floor(rand() * 4)]!;
          decision(
            AUDIT_EVENT_TYPES.AUTHORIZATION_ALLOWED,
            d,
            rand(),
            ti,
            a,
            `project/file-${Math.floor(rand() * 40)}.ts`,
          );
        }
        for (let i = 0; i < ASKED_PER_DAY[d]!; i++) {
          decision(
            AUDIT_EVENT_TYPES.AUTHORIZATION_PENDING_APPROVAL,
            d,
            0.4 + 0.05 * i,
            i % TOOLS.length,
            'bash',
            'sample command',
          );
        }
        for (let i = 0; i < BLOCKED_PER_DAY[d]!; i++) {
          decision(
            AUDIT_EVENT_TYPES.AUTHORIZATION_DENIED,
            d,
            0.6,
            2,
            'bash',
            'sample command',
          );
        }
      }
      // Two secrets kept safe: Codex CLI and Cursor-style reads, masked paths only.
      for (const [day, ti, maskedPath] of [
        [4, 2, '~/code/shop/.env'],
        [6, 2, '~/.ssh/id_ed25519'],
      ] as const) {
        events.push({
          eventType: 'secret.touched' as RecordAuditEventInput['eventType'],
          actor: { type: 'agent', id: agentIds[ti]! },
          timestamp: at(day, 0.45),
          data: {
            toolId: TOOLS[ti].id,
            process: 'sample',
            pathClass: maskedPath.includes('ssh') ? 'ssh-key' : 'env-file',
            maskedPath,
            blocked: true,
            sample: true,
          },
        });
      }
      events.sort((a, b) => a.timestamp!.getTime() - b.timestamp!.getTime());
      publish.push(await audit.recordManyInTransaction(tx, tenantId, events));
    },
    { timeout: 120_000, maxWait: 30_000 },
  );
  // Kafka/OpenSearch fan-out for the sample tenant, after commit.
  publish.forEach((fn) => fn());
}
