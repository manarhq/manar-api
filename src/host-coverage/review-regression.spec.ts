import { describe, expect, it, vi } from 'vitest';
import { LearningService } from '../learning/learning.service';
import { PolicyEngine } from '../policy/policy-engine.service';
import { computeContentHash } from '../policy/policy-content-codec';
import {
  START_MODE_POLICY_NAME,
  START_MODE_PRESETS,
} from '../workspace/start-mode.presets';
import type { HostContext } from '../host-mtls/host-context';
import {
  HostAuthorizeService,
  type HostAuthorizeRequest,
} from './host-authorize.service';

/**
 * The independent review's bypasses (6 Nov 2026), kept as a permanent suite. Real PolicyEngine, real
 * start-mode presets, real HostAuthorizeService and LearningService; only the database is a fake.
 * Each case is an input that once got a quiet answer, or could have, where the answer must be an ask.
 */
const host: HostContext = {
  hostId: 'h1',
  tenantId: 't1',
  machineId: 'm',
  ownerSubject: 'owner',
  status: 'APPROVED',
};
const NOW = Date.now();
const day = (n: number) => new Date(NOW - n * 86_400_000);

type Mode =
  'none' | 'ask' | 'strict' | 'custom' | 'presetAsks' | 'presetAndCustom';
interface Scenario {
  mode?: Mode;
  /** When the device was first approved (days ago). */
  firstApproved?: number;
  /** A person already approved fetches to this origin on this device. */
  siteSeen?: boolean;
  /** Learning switched off for the workspace. */
  learningOff?: boolean;
  /** Scoped grants that exist: pattern and the ask they answer. */
  grants?: Array<{ pattern: string; askKey: string }>;
}

const EDITS_ASK = {
  rules: [
    {
      name: 'Edits in proj wait',
      toolId: '*',
      actionId: 'edit',
      resourcePattern: '/home/sara/proj/*',
      effect: 'APPROVAL_REQUIRED',
    },
  ],
};
const custom = () => ({
  id: 'v-custom',
  policyId: 'p-custom',
  version: 1,
  status: 'PUBLISHED',
  contentHash: 'x',
  content: EDITS_ASK,
});
/**
 * A start-mode policy that is, by its hash, the "ask" preset, whose rules (in this double) also
 * ask about edits: stands for any ask the preset itself raises.
 */
const presetAsks = () => ({
  id: 'v-ask',
  policyId: 'p-start',
  version: 1,
  status: 'PUBLISHED',
  contentHash: computeContentHash(START_MODE_PRESETS.ask),
  content: EDITS_ASK,
});

function version(mode: Mode) {
  if (mode === 'none') return [];
  if (mode === 'custom') return [custom()];
  if (mode === 'presetAsks') return [presetAsks()];
  if (mode === 'presetAndCustom') return [presetAsks(), custom()];
  if ((mode as string) === 'customAndPreset') return [custom(), presetAsks()];
  return [
    {
      id: `v-${mode}`,
      policyId: 'p-start',
      version: 1,
      status: 'PUBLISHED',
      contentHash: computeContentHash(START_MODE_PRESETS[mode]),
      content: START_MODE_PRESETS[mode],
    },
  ];
}

async function run(
  req: Omit<HostAuthorizeRequest, 'caller'>,
  s: Scenario = {},
) {
  const mode = s.mode ?? 'none';
  const versions = version(mode);
  const names: Record<string, string> = {
    'v-custom': 'my-rules',
    'v-ask': START_MODE_POLICY_NAME,
    'v-strict': START_MODE_POLICY_NAME,
  };
  const grants = s.grants ?? [];
  const client = {
    policyVersion: {
      findMany: () => Promise.resolve(versions),
      findUnique: ({ where }: { where: { id: string } }) => {
        const v = versions.find((x) => x.id === where.id);
        return Promise.resolve(
          v
            ? { contentHash: v.contentHash, policy: { name: names[v.id] } }
            : null,
        );
      },
    },
    approvalAllowGrant: {
      findFirst: () => Promise.resolve(null),
      findMany: ({ where }: { where: { askKey: string } }) =>
        Promise.resolve(
          grants
            .filter((g) => g.askKey === where.askKey)
            .map((g, i) => ({
              id: `g${i}`,
              expiresAt: new Date(),
              resourcePattern: g.pattern,
            })),
        ),
      update: () => Promise.resolve({}),
    },
    host: {
      findUnique: () =>
        Promise.resolve({
          firstApprovedAt: day(s.firstApproved ?? 2),
          learningStartedAt: null,
          learningOff: false,
        }),
    },
    hostApproval: {
      findFirst: () => Promise.resolve(s.siteSeen ? { id: 'a' } : null),
    },
    learningObservation: { upsert: vi.fn(() => Promise.resolve({})) },
  };
  const control = {
    tenant: {
      findUnique: () =>
        Promise.resolve({
          kind: 'COMPANY',
          learningMode: s.learningOff ? 'off' : null,
        }),
    },
    enterpriseProfile: { findUnique: () => Promise.resolve(null) },
  };
  const audit = {
    recordSafely: vi
      .fn<(...a: unknown[]) => Promise<unknown>>()
      .mockResolvedValue({ id: 'e' }),
  };
  const open = vi.fn(() =>
    Promise.resolve({ id: 'a1', expiresAt: new Date() }),
  );
  const svc = new HostAuthorizeService(
    { getClient: () => Promise.resolve(client) } as never,
    { checkAll: () => Promise.resolve({ killed: false }) } as never,
    new PolicyEngine({ findToolAction: () => Promise.resolve(null) } as never),
    audit as never,
    { open },
    new LearningService(control as never, audit as never),
  );
  const result = await svc.authorize(host, req);
  const rec = audit.recordSafely.mock.calls.find(
    (c) => (c[2] as { eventType: string }).eventType === 'host.action_decided',
  )![2] as { data: Record<string, unknown> };
  return { result, opened: open.mock.calls.length > 0, record: rec.data };
}

const cursor = (
  actionId: string,
  resource: string,
): Omit<HostAuthorizeRequest, 'caller'> => ({
  toolId: 'host.cursor',
  actionId,
  resource,
  // A device vouches for a file path by sending where it really points.
  ...(['read', 'edit', 'write'].includes(actionId)
    ? { resolvedPath: resource }
    : {}),
});

import { classifyCommand } from '../policy/command-safety';

import { classifyCommand } from '../policy/command-safety';

describe('REVIEW HIGH-1: learning never quiets strict or admin asks', () => {
  it.each([
    ['strict', cursor('edit', '/etc/hosts')],
    ['strict', cursor('write', '/home/sara/.bashrc')],
    ['strict', cursor('shell', 'ls $HOME')],
    ['strict', cursor('webfetch', 'https://docs.x.io/a')],
    ['custom', cursor('edit', '/home/sara/proj/src/a.ts')],
    ['presetAndCustom', cursor('edit', '/home/sara/proj/src/a.ts')],
    ['customAndPreset', cursor('edit', '/home/sara/proj/src/a.ts')],
  ] as Array<[Mode, ReturnType<typeof cursor>]>)(
    '%s %j asks',
    async (mode, req) => {
      const r = await run(req, { mode, siteSeen: true });
      expect(r.result.reason).not.toBe('learning_would_ask');
    },
  );
});

describe('REVIEW HIGH-2: secret reads never quiet', () => {
  it.each([
    cursor('read', '/home/sara/proj/.env'),
    cursor('read', '/home/sara/.ssh/id_rsa'),
    cursor('read', '/home/sara/.aws/credentials'),
    cursor('shell', 'cat .env'),
    cursor('shell', 'cat src/.env'),
    cursor('shell', 'head -n 50 .env.local'),
    cursor('shell', 'cat config/secrets.pem'),
    cursor('edit', '/home/sara/proj/.env'),
  ])('ask preset: %j is not quiet', async (req) => {
    const r = await run(req, { mode: 'ask' });
    expect(r.result.reason).not.toBe('learning_would_ask');
  });

  it.each([
    'grep -rv zzzz .',
    'grep -rh -e KEY .',
    'grep -rn SECRET .',
    'grep -r -i password src',
    'grep -rlv zzzz .',
    'grep -R x .',
    'grep --recursive x .',
    'grep --dereference-recursive x .',
  ])(
    'recursive grep over the tree reads .env/.git/config, so it asks: %s',
    async (c) => {
      expect(classifyCommand(c)).toBeNull();
      const r = await run(cursor('shell', c));
      expect(r.result.decision).toBe('APPROVAL_REQUIRED');
      expect(r.result.reason).not.toBe('learning_would_ask');
    },
  );
});

describe('REVIEW: MCP tools are never quiet while learning', () => {
  it.each([
    'github/delete_repository',
    'postgres/execute_sql',
    'slack/send_message',
    'filesystem/write_file',
  ])('no-rule workspace, learning device: mcp %s asks', async (tool) => {
    const r = await run(cursor('mcp', tool));
    expect(r.result.decision).toBe('APPROVAL_REQUIRED');
    expect(r.result.reason).not.toBe('learning_would_ask');
    expect(r.opened).toBe(true);
  });
});

describe('REVIEW: symlinked folders inside a project', () => {
  const link = (resolvedPath: string | undefined, p: string) => ({
    toolId: 'host.cursor',
    actionId: 'write',
    resource: p,
    resolvedPath,
  });
  it.each([
    ['/home/sara/proj/docs/authorized_keys', '/home/sara/.ssh/authorized_keys'],
    ['/home/sara/proj/k/config', '/home/sara/.kube/config'],
    ['/home/sara/proj/rc/profile', '/home/sara/.bashrc'],
    ['/home/sara/proj/a/b', '/home/sara/proj/c/d'],
    ['/home/sara/proj/a/b', 'relative/b'],
  ])('%s -> %s: the device reports the link, so it asks', async (p, real) => {
    const r = await run(link(real, p));
    expect(r.result.decision).toBe('APPROVAL_REQUIRED');
    expect(r.result.reason).not.toBe('learning_would_ask');
  });

  it('present and the same: quiet. Absent: cannot tell, so it asks', async () => {
    const p = '/home/sara/proj/src/a.ts';
    expect((await run(link(p, p))).result.reason).toBe('learning_would_ask');
    const absent = await run(link(undefined, p));
    expect(absent.result.decision).toBe('APPROVAL_REQUIRED');
    expect(absent.result.reason).not.toBe('learning_would_ask');
  });

  it('present but outside the home project: asks', async () => {
    const r = await run(link('/etc/hosts', '/home/sara/proj/src/a.ts'));
    expect(r.result.decision).toBe('APPROVAL_REQUIRED');
  });
});
