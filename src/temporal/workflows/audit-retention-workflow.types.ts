/**
 * Pure data shapes shared between `AuditRetentionWorkflow` itself and the
 * regular Node code that starts it (tests; a future scheduler) — same
 * "no behavior, no imports" posture `approval-workflow.types.ts`
 * establishes.
 */

export interface AuditRetentionWorkflowInput {
  tenantId: string;
  /** Events older than this many milliseconds (from workflow-execution time) are pruned. Default `DEFAULT_AUDIT_RETENTION_WINDOW_MS` (30 days) — see `src/audit/retention/audit-retention.constants.ts`. */
  retentionWindowMs: number;
}

export interface AuditRetentionWorkflowResult {
  prunedCount: number;
  anchorHash: string | null;
  retentionEventId: string | null;
}
