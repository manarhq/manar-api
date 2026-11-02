import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { AuthContext } from '../auth/auth-context';
import type { RoleName } from '../auth/roles';
import { ApprovalsController } from './approvals.controller';

/**
 * Who may decide an agent's approval (founder decision, 3 Nov 2026): an approver role decides
 * anything; the person who created the agent approves once or denies its requests unless the
 * workspace is "admins only"; nobody else sees it at all.
 */
function world(opts: { adminsOnly?: boolean; paused?: boolean } = {}) {
  const request = {
    id: 'ap1',
    agentId: 'agent-1',
    toolId: 'gitlab',
    actionId: 'merge',
    resource: 'repo/x',
    status: 'PENDING',
    temporalWorkflowId: 'wf-1',
  };
  const client = {
    agent: {
      findUnique: () => Promise.resolve({ createdBy: 'creator' }),
    },
    approvalRequest: {
      findUnique: () => Promise.resolve({ agentId: 'agent-1' }),
    },
    approvalAllowGrant: {
      create: ({ data }: { data: object }) =>
        Promise.resolve({ id: 'g8', ...data }),
    },
    workspacePause: {
      findUnique: () => Promise.resolve(opts.paused ? { paused: true } : null),
    },
  };
  const signal = vi.fn(() => Promise.resolve());
  const temporal = {
    workflow: {
      getHandle: () => ({
        signal,
        result: () => Promise.resolve({ outcome: 'APPROVED', grantId: 'g' }),
      }),
    },
  };
  const approvers = {
    adminsOnly: () => Promise.resolve(opts.adminsOnly ?? false),
  };
  const controller = new ApprovalsController(
    {
      getOrThrow: () => Promise.resolve(request),
      listApprovalRequests: vi.fn(() =>
        Promise.resolve({ items: [], nextCursor: null }),
      ),
    } as never,
    { getClient: () => Promise.resolve(client) } as never,
    temporal as never,
    { get: () => 1000 } as never,
    {} as never,
    { recordSafely: vi.fn() } as never,
    approvers as never,
    {
      revokeAgent: vi.fn(() => Promise.resolve({ status: 'REVOKED' })),
    } as never,
  );
  return { controller, signal };
}

const auth = (userId: string, roles: RoleName[]): AuthContext => ({
  issuer: 'i',
  tenant: { id: 't1', slug: 't' },
  user: {
    id: userId,
    keycloakSubject: `sub-${userId}`,
    email: 'e',
    displayName: 'd',
  },
  roles,
  workspaceKind: 'COMPANY',
});

describe('deciding an agent approval', () => {
  it("a member cannot see or decide someone else's agent's request", async () => {
    const w = world();
    await expect(
      w.controller.decide(auth('a-member', ['DEVELOPER']), 'ap1', {
        decision: 'approve_once',
      }),
    ).rejects.toBeInstanceOf(NotFoundException);
    await expect(
      w.controller.revoke(auth('a-member', ['DEVELOPER']), 'ap1', {}),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(w.signal).not.toHaveBeenCalled();
  });

  it("the agent's creator approves once", async () => {
    const w = world();
    const r = await w.controller.decide(auth('creator', ['DEVELOPER']), 'ap1', {
      decision: 'approve_once',
    });
    expect(r.status).toBe('APPROVED');
    expect(w.signal).toHaveBeenCalledOnce();
  });

  it('the creator cannot give 8 hours or make a rule', async () => {
    const w = world();
    await expect(
      w.controller.decide(auth('creator', ['DEVELOPER']), 'ap1', {
        decision: 'approve_8h',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(
      w.controller.decide(auth('creator', ['DEVELOPER']), 'ap1', {
        decision: 'approve_once',
        makeRule: true,
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('"admins only" stops the creator but not an approver', async () => {
    const w = world({ adminsOnly: true });
    await expect(
      w.controller.decide(auth('creator', ['DEVELOPER']), 'ap1', {
        decision: 'deny',
      }),
    ).rejects.toBeInstanceOf(ForbiddenException);
    const r = await w.controller.decide(auth('boss', ['APPROVER']), 'ap1', {
      decision: 'approve_8h',
    });
    expect(r.status).toBe('APPROVED');
  });

  it('approving while AI is paused says paused, not "already decided" (E-021)', async () => {
    const w = world({ paused: true });
    await expect(
      w.controller.decide(auth('boss', ['APPROVER']), 'ap1', {
        decision: 'approve_once',
      }),
    ).rejects.toMatchObject({ status: 409, response: { reason: 'paused' } });
  });

  it("a member lists only their own agents' requests", async () => {
    const w = world();
    const svc = (
      w.controller as unknown as {
        approvalRequestService: {
          listApprovalRequests: ReturnType<typeof vi.fn>;
        };
      }
    ).approvalRequestService;
    await w.controller.list(auth('a-member', ['DEVELOPER']));
    expect(svc.listApprovalRequests.mock.calls[0]![1]).toMatchObject({
      agentCreatedBy: 'a-member',
    });
    await w.controller.list(auth('boss', ['SECURITY_ADMIN']));
    expect(svc.listApprovalRequests.mock.calls[1]![1]).not.toHaveProperty(
      'agentCreatedBy',
    );
  });
});
