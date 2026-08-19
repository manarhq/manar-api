import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TestWorkflowEnvironment } from '@temporalio/testing';
import { Worker } from '@temporalio/worker';
import type { WebhookDeliveryActivities } from '../activities/webhook-delivery-activities.interface';
import { WebhookDeliveryWorkflow } from './webhook-delivery.workflow';

/**
 * `WebhookDeliveryWorkflow`'s own decision logic — mirrors
 * `audit-retention.workflow.spec.ts`'s reusable
 * time-skipping-`TestWorkflowEnvironment` + mocked-Activities pattern.
 * Time-skipping is what makes proving the FULL retry-then-give-up path
 * fast and deterministic here (the workflow's own hardcoded retry policy
 * spans up to several real minutes of backoff — see that file's doc
 * comment) rather than needing `test/webhooks.e2e-spec.ts`'s real end-to-end
 * suite to actually wait through it.
 */
describe('WebhookDeliveryWorkflow (time-skipping TestWorkflowEnvironment)', () => {
  let testEnv: TestWorkflowEnvironment;

  beforeEach(async () => {
    testEnv = await TestWorkflowEnvironment.createTimeSkipping();
  }, 30_000);

  afterEach(async () => {
    await testEnv?.teardown();
  });

  async function createWorker(
    activities: WebhookDeliveryActivities,
  ): Promise<Worker> {
    return Worker.create({
      connection: testEnv.nativeConnection,
      taskQueue: 'webhook-delivery-workflow-test',
      workflowsPath: join(__dirname, 'webhook-delivery.workflow.ts'),
      activities,
    });
  }

  it('a successful first attempt resolves DELIVERED and never calls markWebhookDeliveryFailed', async () => {
    const deliverWebhookAttempt = vi
      .fn()
      .mockResolvedValue({ responseStatus: 200 });
    const markWebhookDeliveryFailed = vi.fn().mockResolvedValue(undefined);
    const worker = await createWorker({
      deliverWebhookAttempt,
      markWebhookDeliveryFailed,
    });

    const result = await worker.runUntil(
      testEnv.client.workflow.execute(WebhookDeliveryWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'webhook-delivery-workflow-test',
        args: [{ tenantId: 'tenant-1', webhookDeliveryId: 'delivery-1' }],
      }),
    );

    expect(result).toEqual({ outcome: 'DELIVERED' });
    expect(deliverWebhookAttempt).toHaveBeenCalledExactlyOnceWith({
      tenantId: 'tenant-1',
      webhookDeliveryId: 'delivery-1',
    });
    expect(markWebhookDeliveryFailed).not.toHaveBeenCalled();
  }, 30_000);

  it('an endpoint that always fails exhausts the configured retry policy (6 attempts), then calls markWebhookDeliveryFailed and resolves FAILED', async () => {
    const deliverWebhookAttempt = vi
      .fn()
      .mockRejectedValue(new Error('receiver unreachable'));
    const markWebhookDeliveryFailed = vi.fn().mockResolvedValue(undefined);
    const worker = await createWorker({
      deliverWebhookAttempt,
      markWebhookDeliveryFailed,
    });

    const result = await worker.runUntil(
      testEnv.client.workflow.execute(WebhookDeliveryWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'webhook-delivery-workflow-test',
        args: [{ tenantId: 'tenant-1', webhookDeliveryId: 'delivery-2' }],
      }),
    );

    expect(result).toEqual({ outcome: 'FAILED' });
    // The workflow's hardcoded retry policy (webhook-delivery.workflow.ts):
    // maximumAttempts: 6 -- every attempt failed, so the Activity was
    // called exactly 6 times before Temporal gave up and let the
    // rejection propagate to this workflow's own catch block.
    expect(deliverWebhookAttempt).toHaveBeenCalledTimes(6);
    expect(markWebhookDeliveryFailed).toHaveBeenCalledExactlyOnceWith({
      tenantId: 'tenant-1',
      webhookDeliveryId: 'delivery-2',
    });
  }, 30_000);

  it('a receiver that fails twice then succeeds is delivered without ever calling markWebhookDeliveryFailed (proves real retry, not just an all-or-nothing outcome)', async () => {
    let call = 0;
    const deliverWebhookAttempt = vi.fn().mockImplementation(() => {
      call += 1;
      if (call <= 2) return Promise.reject(new Error('transient failure'));
      return Promise.resolve({ responseStatus: 200 });
    });
    const markWebhookDeliveryFailed = vi.fn().mockResolvedValue(undefined);
    const worker = await createWorker({
      deliverWebhookAttempt,
      markWebhookDeliveryFailed,
    });

    const result = await worker.runUntil(
      testEnv.client.workflow.execute(WebhookDeliveryWorkflow, {
        workflowId: `wf-${randomUUID()}`,
        taskQueue: 'webhook-delivery-workflow-test',
        args: [{ tenantId: 'tenant-1', webhookDeliveryId: 'delivery-3' }],
      }),
    );

    expect(result).toEqual({ outcome: 'DELIVERED' });
    expect(deliverWebhookAttempt).toHaveBeenCalledTimes(3);
    expect(markWebhookDeliveryFailed).not.toHaveBeenCalled();
  }, 30_000);
});
