import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TestWorkflowEnvironment } from '@temporalio/testing';
import { Worker } from '@temporalio/worker';
import type { AuditRetentionActivities } from '../activities/audit-retention-activities.interface';
import { AuditRetentionWorkflow } from './audit-retention.workflow';

/**
 * Section 28/48's "add unit/integration coverage for workflows" — the
 * workflow's own "call the one Activity, return its result" logic,
 * exercised with `@temporalio/testing`'s `TestWorkflowEnvironment`, the
 * exact same reusable pattern `approval.workflow.spec.ts` establishes
 * (mocked Activities — this suite proves `AuditRetentionWorkflow` calls
 * `pruneAuditEvents` with the right input and returns its result verbatim,
 * not what `AuditRetentionService.pruneTenantAuditEvents` itself does —
 * that's `test/audit-retention.e2e-spec.ts`'s job, against real Postgres/
 * Temporal).
 */
describe('AuditRetentionWorkflow (time-skipping TestWorkflowEnvironment)', () => {
  let testEnv: TestWorkflowEnvironment;

  beforeEach(async () => {
    testEnv = await TestWorkflowEnvironment.createTimeSkipping();
  }, 30_000);

  afterEach(async () => {
    await testEnv?.teardown();
  });

  async function createWorker(
    activities: AuditRetentionActivities,
  ): Promise<Worker> {
    return Worker.create({
      connection: testEnv.nativeConnection,
      taskQueue: 'audit-retention-workflow-test',
      workflowsPath: join(__dirname, 'audit-retention.workflow.ts'),
      activities,
    });
  }

  it('calls pruneAuditEvents with the workflow input and returns its result verbatim', async () => {
    const pruneAuditEvents = vi.fn().mockResolvedValue({
      prunedCount: 3,
      anchorHash: 'a'.repeat(64),
      retentionEventId: 'retention-event-1',
    });
    const worker = await createWorker({ pruneAuditEvents });

    const result = await worker.runUntil(
      testEnv.client.workflow.execute(AuditRetentionWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'audit-retention-workflow-test',
        args: [
          { tenantId: 'tenant-1', retentionWindowMs: 30 * 24 * 60 * 60 * 1000 },
        ],
      }),
    );

    expect(result).toEqual({
      prunedCount: 3,
      anchorHash: 'a'.repeat(64),
      retentionEventId: 'retention-event-1',
    });
    expect(pruneAuditEvents).toHaveBeenCalledExactlyOnceWith({
      tenantId: 'tenant-1',
      retentionWindowMs: 30 * 24 * 60 * 60 * 1000,
    });
  }, 30_000);

  it('a no-op prune (nothing old enough) still resolves the workflow, with no anchor/retention event', async () => {
    const pruneAuditEvents = vi.fn().mockResolvedValue({
      prunedCount: 0,
      anchorHash: null,
      retentionEventId: null,
    });
    const worker = await createWorker({ pruneAuditEvents });

    const result = await worker.runUntil(
      testEnv.client.workflow.execute(AuditRetentionWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'audit-retention-workflow-test',
        args: [{ tenantId: 'tenant-2', retentionWindowMs: 1_000 }],
      }),
    );

    expect(result).toEqual({
      prunedCount: 0,
      anchorHash: null,
      retentionEventId: null,
    });
  }, 30_000);
});
