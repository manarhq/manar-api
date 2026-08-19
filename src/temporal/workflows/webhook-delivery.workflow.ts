import { proxyActivities } from '@temporalio/workflow';
import type { WebhookDeliveryActivities } from '../activities/webhook-delivery-activities.interface';
import type {
  WebhookDeliveryWorkflowInput,
  WebhookDeliveryWorkflowResult,
} from './webhook-delivery-workflow.types';

/**
 * `import type` only, the same "erased from the compiled workflow bundle"
 * reasoning `approval.workflow.ts`/`audit-retention.workflow.ts` already
 * establish — the real implementation
 * (`../activities/webhook-delivery.activities.ts`) is Nest/Prisma/`fetch`
 * code that must never enter this workflow's deterministic sandbox.
 *
 * **Real Temporal retry-policy configuration** (Section 51's "research
 * Temporal's retry policy configuration rather than hand-rolling a backoff
 * loop" requirement) — `deliverWebhookAttempt` throwing is what triggers
 * this, exactly the same `proxyActivities({ retry: {...} })` mechanism
 * `ApprovalWorkflow`/`AuditRetentionWorkflow` already use for their own
 * Activities, not a second, hand-rolled implementation. Exponential
 * backoff starting at 5 seconds, doubling up to a 5-minute ceiling, for up
 * to 6 total attempts (roughly a 20-minute delivery window end to end:
 * 5s+10s+20s+40s+80s+160s between the 6 attempts, then capped) — generous
 * enough to ride out a receiver's brief restart/redeploy without giving up
 * immediately, bounded enough that a permanently-dead receiver's
 * `WebhookDelivery` reaches a terminal `FAILED` state in a reasonable time
 * rather than retrying forever. Mirrors `WEBHOOK_DELIVERY_MAX_ATTEMPTS`'s
 * default (`src/webhooks/webhooks.config.ts`) — kept as a literal here
 * rather than threaded from runtime config, the same reason every other
 * workflow file in this codebase hardcodes its own retry policy: workflow
 * code must be deterministic, and reading process env/DI config from
 * inside a workflow is exactly the kind of non-determinism Temporal's
 * sandbox forbids.
 */
const activities = proxyActivities<WebhookDeliveryActivities>({
  startToCloseTimeout: '30 seconds',
  retry: {
    initialInterval: '5 seconds',
    backoffCoefficient: 2,
    maximumInterval: '5 minutes',
    maximumAttempts: 6,
  },
});

/**
 * One `WebhookDeliveryWorkflow` execution = one `WebhookDelivery` row's
 * full attempt history, from the first attempt through either a
 * successful delivery or Temporal's retry policy being exhausted. Started
 * by `WebhookDeliveryConsumerService` the moment a subscribed event is
 * consumed off Kafka for a matching, enabled `WebhookEndpoint` (see
 * `src/webhooks/webhook-delivery-consumer.service.ts`).
 *
 * All real work (loading the delivery/endpoint rows, the call-time SSRF
 * re-check, signing, the actual `fetch`, and recording each attempt's
 * outcome) happens inside `deliverWebhookAttempt` -- this function only
 * calls it once and lets Temporal's own retry policy above call it again
 * on failure, exactly like `AuditRetentionWorkflow`'s "all the work is in
 * the Activity" shape. The one piece of workflow-level decision-making:
 * once every retry is exhausted, `deliverWebhookAttempt`'s final rejection
 * propagates here, and this workflow calls `markWebhookDeliveryFailed`
 * itself (a workflow decision — "give up," not an Activity's own call to
 * make) to leave the `WebhookDelivery` row in a genuine terminal `FAILED`
 * state rather than stuck at whatever `PENDING`-with-attempts state the
 * last failed attempt left it in.
 */
export async function WebhookDeliveryWorkflow(
  input: WebhookDeliveryWorkflowInput,
): Promise<WebhookDeliveryWorkflowResult> {
  try {
    await activities.deliverWebhookAttempt({
      tenantId: input.tenantId,
      webhookDeliveryId: input.webhookDeliveryId,
    });
    return { outcome: 'DELIVERED' };
  } catch {
    await activities.markWebhookDeliveryFailed({
      tenantId: input.tenantId,
      webhookDeliveryId: input.webhookDeliveryId,
    });
    return { outcome: 'FAILED' };
  }
}
