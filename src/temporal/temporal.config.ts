import { z } from 'zod';

/**
 * Phase 8 (Approval Engine): connection settings for both the Temporal
 * *client* (the main HTTP process — starts `ApprovalWorkflow`, signals it
 * on `POST /approvals/:id/decide`) and the separate Temporal *worker*
 * process (`src/worker.main.ts`, `pnpm worker`) — both read this exact
 * schema, so they're always talking about the same server/namespace/task
 * queue without a second place either could drift from. See
 * docs/approvals.md.
 */
export const TemporalConfigSchema = z.object({
  /** `host:port` of the Temporal frontend service — matches deploy/docker-compose.yml's `temporal` service. */
  TEMPORAL_ADDRESS: z.string().min(1).default('localhost:7233'),
  /** Matches deploy/docker-compose.yml's `temporal` service, which auto-creates and uses this namespace by default. */
  TEMPORAL_NAMESPACE: z.string().min(1).default('default'),
  /** The task queue `ApprovalWorkflow`/its Activities are dispatched on — the client starts/signals workflows on this queue, and the worker process polls it. */
  TEMPORAL_TASK_QUEUE: z.string().min(1).default('manar-approvals'),
});

export type TemporalConfig = z.infer<typeof TemporalConfigSchema>;
