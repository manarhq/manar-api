/**
 * `import type` only from `webhook-delivery.workflow.ts` — the same
 * "erased entirely from the workflow's compiled bundle" pattern every
 * other Activities interface in this codebase establishes (Section 28: no
 * I/O in workflow code). The real implementation
 * (`webhook-delivery.activities.ts`) is Nest/Prisma/`fetch` code that runs
 * only in the separate worker process.
 */

export interface WebhookDeliveryActivityInput {
  tenantId: string;
  webhookDeliveryId: string;
}

export interface DeliverWebhookAttemptResult {
  responseStatus: number | null;
}

export interface WebhookDeliveryActivities {
  /**
   * One real delivery attempt. Throws on any failure (network error,
   * non-2xx, or a failed call-time SSRF re-check) — Temporal's own
   * `proxyActivities` retry policy (`webhook-delivery.workflow.ts`) is what
   * actually retries this, not any loop inside the Activity itself.
   */
  deliverWebhookAttempt(
    input: WebhookDeliveryActivityInput,
  ): Promise<DeliverWebhookAttemptResult>;

  /** Terminal state after every retry attempt has been exhausted — called exactly once, by the workflow's own catch. */
  markWebhookDeliveryFailed(input: WebhookDeliveryActivityInput): Promise<void>;
}
