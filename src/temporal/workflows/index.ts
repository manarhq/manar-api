/**
 * Temporal's `Worker.create({ workflowsPath })` bundles exactly one entry
 * file into the deterministic sandbox — this re-exports every workflow
 * function (and signal) `src/worker.main.ts`'s single `Worker` needs to
 * register, so adding a second workflow (Phase 9b's `AuditRetentionWorkflow`,
 * alongside Phase 8's `ApprovalWorkflow`) never requires a second `Worker`
 * instance/task-queue poller.
 */
export { ApprovalWorkflow, decideSignal } from './approval.workflow';
export { AuditRetentionWorkflow } from './audit-retention.workflow';
export { WebhookDeliveryWorkflow } from './webhook-delivery.workflow';
export { GrowthTickWorkflow } from './growth-tick.workflow';
export { PolicySuggestWorkflow } from './policy-suggest.workflow';
