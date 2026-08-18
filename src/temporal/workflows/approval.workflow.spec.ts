import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TestWorkflowEnvironment } from '@temporalio/testing';
import { Worker } from '@temporalio/worker';
import type { ApprovalActivities } from '../activities/approval-activities.interface';
import { ApprovalWorkflow, decideSignal } from './approval.workflow';

/**
 * Section 28's "add unit/integration coverage for workflows" — the
 * workflow's own approve/deny/timeout logic, exercised with
 * `@temporalio/testing`'s time-skipping `TestWorkflowEnvironment`
 * (docs/approvals.md), independent of any real Postgres/HTTP e2e
 * infrastructure. Activities are mocked (`vi.fn()`) — this suite proves
 * `ApprovalWorkflow` calls the *right* Activity with the *right* input in
 * each branch and returns the *right* result, not what
 * `GrantService.finalizeDecision`/`expire` themselves do (that's the e2e
 * suite's job).
 *
 * The timeout scenario in particular is exactly what the time-skipping
 * environment exists for: a real-time e2e test would need to actually
 * wait out `APPROVAL_REQUEST_TTL_MS` (30 minutes by default) — this test
 * uses a short timeout and the test server's automatic time-skipping (no
 * Activity in flight -> skip straight to the next timer) to observe the
 * same behavior in a couple of seconds of real wall-clock time.
 *
 * A brand new `TestWorkflowEnvironment` + `Worker` is created per test
 * (`beforeEach`/`afterEach`), each torn down immediately after — chaining
 * many workflow executions through one shared, long-lived environment/
 * worker/`runUntil` call in this SDK version was observed to hang
 * intermittently on every test after the first (a native-bridge/test
 * -server state issue, not anything about this workflow's own logic);
 * full per-test isolation avoids it entirely, at the cost of ~1-2s of
 * startup overhead per test, well within this suite's generous per-test
 * timeout.
 */
describe('ApprovalWorkflow (time-skipping TestWorkflowEnvironment)', () => {
  let testEnv: TestWorkflowEnvironment;

  beforeEach(async () => {
    testEnv = await TestWorkflowEnvironment.createTimeSkipping();
  }, 30_000);

  afterEach(async () => {
    await testEnv?.teardown();
  });

  function mockActivities(
    overrides: Partial<ApprovalActivities> = {},
  ): ApprovalActivities {
    return {
      finalizeApprovalDecision: vi
        .fn()
        .mockResolvedValue({ status: 'APPROVED', grantId: 'default-grant' }),
      expireApprovalRequest: vi.fn().mockResolvedValue(undefined),
      ...overrides,
    };
  }

  async function createWorker(activities: ApprovalActivities): Promise<Worker> {
    return Worker.create({
      connection: testEnv.nativeConnection,
      taskQueue: 'approval-workflow-test',
      // `require.resolve` isn't reliable for a real, on-disk TS module
      // path from inside vitest's own transform sandbox — a plain
      // filesystem path (Temporal's own bundler only needs a real path to
      // read from disk, never Node's module resolution algorithm) works
      // identically here and when this same workflow is loaded from
      // compiled `dist/` in `src/worker.main.ts`.
      workflowsPath: join(__dirname, 'approval.workflow.ts'),
      activities,
    });
  }

  it('an APPROVE signal before the timeout calls finalizeApprovalDecision and returns APPROVED', async () => {
    const finalizeApprovalDecision = vi
      .fn()
      .mockResolvedValue({ status: 'APPROVED', grantId: 'grant-approve-1' });
    const expireApprovalRequest = vi.fn().mockResolvedValue(undefined);
    const activities = mockActivities({
      finalizeApprovalDecision,
      expireApprovalRequest,
    });
    const worker = await createWorker(activities);

    const result = await worker.runUntil(async () => {
      const handle = await testEnv.client.workflow.start(ApprovalWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'approval-workflow-test',
        args: [
          {
            tenantId: 'tenant-1',
            approvalRequestId: 'approval-1',
            expiresAtEpochMs: Date.now() + 10 * 60 * 1000,
          },
        ],
      });
      await handle.signal(decideSignal, {
        decision: 'APPROVE',
        approverId: 'approver-1',
        reason: 'looks fine',
      });
      return handle.result();
    });

    expect(result).toEqual({
      outcome: 'APPROVED',
      grantId: 'grant-approve-1',
    });
    expect(finalizeApprovalDecision).toHaveBeenCalledExactlyOnceWith({
      tenantId: 'tenant-1',
      approvalRequestId: 'approval-1',
      decision: 'APPROVE',
      approverId: 'approver-1',
      reason: 'looks fine',
    });
    expect(expireApprovalRequest).not.toHaveBeenCalled();
  }, 30_000);

  it('a DENY signal before the timeout calls finalizeApprovalDecision and returns DENIED', async () => {
    const finalizeApprovalDecision = vi
      .fn()
      .mockResolvedValue({ status: 'DENIED' });
    const expireApprovalRequest = vi.fn().mockResolvedValue(undefined);
    const activities = mockActivities({
      finalizeApprovalDecision,
      expireApprovalRequest,
    });
    const worker = await createWorker(activities);

    const result = await worker.runUntil(async () => {
      const handle = await testEnv.client.workflow.start(ApprovalWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'approval-workflow-test',
        args: [
          {
            tenantId: 'tenant-1',
            approvalRequestId: 'approval-2',
            expiresAtEpochMs: Date.now() + 10 * 60 * 1000,
          },
        ],
      });
      await handle.signal(decideSignal, {
        decision: 'DENY',
        approverId: 'approver-2',
        reason: 'too risky',
      });
      return handle.result();
    });

    expect(result).toEqual({ outcome: 'DENIED' });
    expect(finalizeApprovalDecision).toHaveBeenCalledExactlyOnceWith({
      tenantId: 'tenant-1',
      approvalRequestId: 'approval-2',
      decision: 'DENY',
      approverId: 'approver-2',
      reason: 'too risky',
    });
    expect(expireApprovalRequest).not.toHaveBeenCalled();
  }, 30_000);

  it('a grantId-less APPROVED result from finalizeApprovalDecision (re-evaluation denied it) still resolves the workflow to DENIED', async () => {
    // Defense in depth at the workflow level: even if an Activity
    // somehow returned status "APPROVED" without a grantId (it
    // shouldn't — GrantService always pairs them — see
    // grant.service.ts), the workflow itself never fabricates a result
    // claiming a grant exists.
    const finalizeApprovalDecision = vi
      .fn()
      .mockResolvedValue({ status: 'APPROVED' });
    const activities = mockActivities({ finalizeApprovalDecision });
    const worker = await createWorker(activities);

    const result = await worker.runUntil(async () => {
      const handle = await testEnv.client.workflow.start(ApprovalWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'approval-workflow-test',
        args: [
          {
            tenantId: 'tenant-1',
            approvalRequestId: 'approval-3',
            expiresAtEpochMs: Date.now() + 10 * 60 * 1000,
          },
        ],
      });
      await handle.signal(decideSignal, {
        decision: 'APPROVE',
        approverId: 'approver-3',
      });
      return handle.result();
    });

    expect(result).toEqual({ outcome: 'DENIED' });
  }, 30_000);

  it('nobody deciding before expiresAt calls expireApprovalRequest and returns EXPIRED, without ever calling finalizeApprovalDecision', async () => {
    const finalizeApprovalDecision = vi
      .fn()
      .mockResolvedValue({ status: 'APPROVED', grantId: 'unused' });
    const expireApprovalRequest = vi.fn().mockResolvedValue(undefined);
    const activities = mockActivities({
      finalizeApprovalDecision,
      expireApprovalRequest,
    });
    const worker = await createWorker(activities);

    const result = await worker.runUntil(
      testEnv.client.workflow.execute(ApprovalWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'approval-workflow-test',
        args: [
          {
            tenantId: 'tenant-1',
            approvalRequestId: 'approval-4',
            // Short timeout -- the time-skipping test server advances
            // virtual time straight to this instant since no signal
            // ever arrives and no Activity is in flight in the
            // meantime.
            expiresAtEpochMs: Date.now() + 5_000,
          },
        ],
      }),
    );

    expect(result).toEqual({ outcome: 'EXPIRED' });
    expect(expireApprovalRequest).toHaveBeenCalledExactlyOnceWith({
      tenantId: 'tenant-1',
      approvalRequestId: 'approval-4',
    });
    expect(finalizeApprovalDecision).not.toHaveBeenCalled();
  }, 30_000);

  it('a second decide signal after the first is ignored (first decision wins)', async () => {
    const finalizeApprovalDecision = vi
      .fn()
      .mockResolvedValue({ status: 'DENIED' });
    const activities = mockActivities({ finalizeApprovalDecision });
    const worker = await createWorker(activities);

    const result = await worker.runUntil(async () => {
      const handle = await testEnv.client.workflow.start(ApprovalWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'approval-workflow-test',
        args: [
          {
            tenantId: 'tenant-1',
            approvalRequestId: 'approval-5',
            expiresAtEpochMs: Date.now() + 10 * 60 * 1000,
          },
        ],
      });
      await handle.signal(decideSignal, {
        decision: 'DENY',
        approverId: 'approver-first',
      });
      await handle.signal(decideSignal, {
        decision: 'APPROVE',
        approverId: 'approver-second',
      });
      return handle.result();
    });

    expect(result).toEqual({ outcome: 'DENIED' });
    expect(finalizeApprovalDecision).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        approverId: 'approver-first',
        decision: 'DENY',
      }),
    );
  }, 30_000);
});
