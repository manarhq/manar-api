/** Thrown by `WebhookDeliveryService.attemptDelivery` on any failed attempt (network error, non-2xx response, or the outbound URL failing the call-time SSRF re-check) — the DB row is already updated with this attempt's outcome before this is thrown. Temporal's `WebhookDeliveryWorkflow` retry policy (`src/temporal/workflows/webhook-delivery.workflow.ts`) is what actually retries the call; this error is simply what tells Temporal "this attempt failed, retry per policy." */
export class WebhookDeliveryAttemptFailedError extends Error {
  constructor(reason: string) {
    super(`Webhook delivery attempt failed: ${reason}`);
    this.name = 'WebhookDeliveryAttemptFailedError';
  }
}
