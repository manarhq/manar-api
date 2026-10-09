import { describe, expect, it, vi } from 'vitest';
import type { AgentContext } from '../agent-mtls/agent-context';
import type { ToolInvocationService } from '../tools/tool-invocation.service';
import {
  AgentRuntimeController,
  ApprovalStatusArgsSchema,
  MAX_CONCURRENT_APPROVAL_WAITS_PER_AGENT,
} from './agent-runtime.controller';
import type { AgentTaskAccessService } from './agent-task-access.service';
import type { ToolManifestService } from './tool-manifest.service';

/**
 * `manar_approval_status` (ADR-0007): bounded, cancellable, capped per agent,
 * fail closed.
 */

const AGENT = {
  tenant: { id: 'tenant-1' },
  agent: { id: 'agent-1' },
} as unknown as AgentContext;

const PENDING_ROW = {
  id: 'approval-1',
  status: 'PENDING',
  agentId: 'agent-1',
  taskId: 'task-1',
  toolId: 'microsoft-graph',
  actionId: 'entra.user.disable',
  resource: 'user-1',
  expiresAt: new Date(Date.now() + 600_000),
  grant: null,
};

function controllerOver(findUnique: ReturnType<typeof vi.fn>) {
  const access = {
    assertTaskAccess: vi.fn().mockResolvedValue({
      tenantClient: { approvalRequest: { findUnique } },
    }),
  } as unknown as AgentTaskAccessService;
  return new AgentRuntimeController(
    access,
    {} as ToolManifestService,
    {} as ToolInvocationService,
  );
}

describe('manar_approval_status arguments', () => {
  it('waits 25 s by default and at most 50 s, under the MCP SDK 60 s request timeout', () => {
    expect(
      ApprovalStatusArgsSchema.parse({ approvalId: 'a' }).waitSeconds,
    ).toBe(25);
    expect(
      ApprovalStatusArgsSchema.safeParse({ approvalId: 'a', waitSeconds: 50 })
        .success,
    ).toBe(true);
    expect(
      ApprovalStatusArgsSchema.safeParse({ approvalId: 'a', waitSeconds: 51 })
        .success,
    ).toBe(false);
  });
});

describe('manar_approval_status wait', () => {
  it('stops polling as soon as the client goes away', async () => {
    const findUnique = vi.fn().mockResolvedValue(PENDING_ROW);
    const controller = controllerOver(findUnique);
    const abort = new AbortController();
    setTimeout(() => abort.abort(), 50);

    const started = Date.now();
    const result = await controller.approvalStatus(
      AGENT,
      'task-1',
      { approvalId: 'approval-1', waitSeconds: 50 },
      abort.signal,
    );

    expect(Date.now() - started).toBeLessThan(1_000);
    expect(findUnique).toHaveBeenCalledOnce();
    expect(result.structuredContent).toMatchObject({ status: 'PENDING' });
  });

  it('a store failure during a poll fails closed with enforcement_dependency_unavailable', async () => {
    const findUnique = vi
      .fn()
      .mockRejectedValue(new Error('connection terminated'));
    const controller = controllerOver(findUnique);

    const result = await controller.approvalStatus(AGENT, 'task-1', {
      approvalId: 'approval-1',
      waitSeconds: 0,
    });

    expect(result).toMatchObject({
      isError: true,
      structuredContent: {
        status: 'DENIED',
        reason: 'enforcement_dependency_unavailable',
      },
    });
  });

  it(`over ${MAX_CONCURRENT_APPROVAL_WAITS_PER_AGENT} waits for one agent: answers the current status at once`, async () => {
    const findUnique = vi.fn().mockResolvedValue(PENDING_ROW);
    const controller = controllerOver(findUnique);
    const abort = new AbortController();
    const holding = Array.from(
      { length: MAX_CONCURRENT_APPROVAL_WAITS_PER_AGENT },
      () =>
        controller.approvalStatus(
          AGENT,
          'task-1',
          { approvalId: 'approval-1', waitSeconds: 50 },
          abort.signal,
        ),
    );
    await vi.waitFor(() =>
      expect(findUnique).toHaveBeenCalledTimes(
        MAX_CONCURRENT_APPROVAL_WAITS_PER_AGENT,
      ),
    );

    const started = Date.now();
    const extra = await controller.approvalStatus(AGENT, 'task-1', {
      approvalId: 'approval-1',
      waitSeconds: 50,
    });

    expect(Date.now() - started).toBeLessThan(1_000);
    expect(extra.structuredContent).toMatchObject({ status: 'PENDING' });
    abort.abort();
    await Promise.all(holding);

    // The slots are released: a new wait waits again.
    const again = new AbortController();
    const waiting = controller.approvalStatus(
      AGENT,
      'task-1',
      { approvalId: 'approval-1', waitSeconds: 50 },
      again.signal,
    );
    const settled = await Promise.race([
      waiting.then(() => 'returned'),
      new Promise((resolve) => setTimeout(() => resolve('waiting'), 200)),
    ]);
    expect(settled).toBe('waiting');
    again.abort();
    await waiting;
  });
});
