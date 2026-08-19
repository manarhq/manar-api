import { z } from 'zod';

/**
 * Phase 12a (Webhooks, Section 51). See docs/security.md's webhook-signing
 * section for the full scheme this config drives:
 * `WebhookDeliveryService`/`WebhookSigner` sign every delivery with
 * `HMAC-SHA256(secret, "<timestamp>.<body>")`, sent as the
 * `Manar-Signature`/`Manar-Timestamp` headers.
 */
export const WebhooksConfigSchema = z.object({
  /**
   * A **dedicated** Temporal task queue for `WebhookDeliveryWorkflow`,
   * deliberately separate from `TEMPORAL_TASK_QUEUE` (`ApprovalWorkflow`/
   * `AuditRetentionWorkflow`'s shared queue) — not because production needs
   * two queues (a single worker process already bundles every workflow
   * type via `workflowsPath`, see `src/worker.main.ts`'s own doc comment
   * on why this codebase deliberately avoids "a second Worker/task queue
   * per workflow" as a general pattern), but because this repo's e2e
   * suites each spin up their *own* in-process Temporal worker
   * (`test/kill-switches.e2e-spec.ts`, `test/approvals.e2e-spec.ts`,
   * etc.), several of which narrowly bundle only `approval.workflow.ts`
   * (not the full `index.ts`) and would crash
   * ("no such function is exported by the workflow bundle") if a
   * `WebhookDeliveryWorkflow` task ever landed on the same shared queue
   * they're polling — a real cross-test-file interference hazard that
   * only exists because of how many independently-configured in-process
   * workers this test suite runs concurrently, not a production concern.
   * `src/worker.main.ts` still runs one process, just with a second
   * `Worker.create()` call for this queue.
   */
  WEBHOOK_DELIVERY_TASK_QUEUE: z.string().min(1).default('manar-webhooks'),

  /**
   * How far a delivery's `Manar-Timestamp` may drift from "now" before a
   * receiver should treat the request as a replay and reject it — the
   * signing scheme's documented replay-protection window. Not enforced by
   * `manar-api` itself (it's the *sender*, never a receiver of its own
   * webhooks) — this constant exists so `docs/security.md`'s documented
   * scheme and every receiver-side verification example this repo ships
   * (see that doc) agree on one number, and so `WebhookSigner`'s own tests
   * assert against the real configured value rather than a hand-copied
   * literal.
   */
  WEBHOOK_SIGNATURE_TOLERANCE_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(5 * 60 * 1000),

  /** Per-attempt HTTP timeout for a webhook delivery POST. */
  WEBHOOK_DELIVERY_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(10_000),

  /** Max total delivery attempts (Temporal retry policy) before a `WebhookDelivery` is recorded as permanently `FAILED`. */
  WEBHOOK_DELIVERY_MAX_ATTEMPTS: z.coerce.number().int().positive().default(6),
});

export type WebhooksConfig = z.infer<typeof WebhooksConfigSchema>;
