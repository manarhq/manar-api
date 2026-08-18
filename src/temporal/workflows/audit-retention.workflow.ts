import { proxyActivities } from '@temporalio/workflow';
import type { AuditRetentionActivities } from '../activities/audit-retention-activities.interface';
import type {
  AuditRetentionWorkflowInput,
  AuditRetentionWorkflowResult,
} from './audit-retention-workflow.types';

/**
 * `import type` only, same "erased entirely from this file's compiled
 * output" reasoning `approval.workflow.ts`'s own doc comment gives — the
 * real implementation (`../activities/audit-retention.activities.ts`) is
 * Prisma/Nest code that must never be pulled into this workflow's
 * deterministic sandbox.
 */
const activities = proxyActivities<AuditRetentionActivities>({
  // Deleting/anchoring a genuinely large aged-out batch is the one thing
  // this Activity does that could plausibly take longer than
  // `ApprovalWorkflow`'s Activities' own 30-second budget — a generous
  // fixed ceiling, not a tuned value, since this phase's own test data
  // volumes are tiny.
  startToCloseTimeout: '2 minutes',
  retry: {
    initialInterval: '1 second',
    backoffCoefficient: 2,
    maximumInterval: '30 seconds',
    maximumAttempts: 5,
  },
});

/**
 * Phase 9b (Retention, Section 48). One execution = one retention pass for
 * one tenant. Deliberately simple compared to `ApprovalWorkflow`: no
 * signal to wait for, no timeout race — retention has nothing to wait
 * *for*, it just runs once and returns. All the actual work (finding aged
 * events, anchoring, deleting, recording `audit.retention_executed`)
 * happens inside the single `pruneAuditEvents` Activity (Section 28: no
 * I/O in workflow code) — this function only calls it and returns its
 * result.
 *
 * Not wired to any automatic Temporal Schedule this phase (see
 * `docs/audit-chain.md`'s "Retention" section for why this deliberately
 * stops short of standing up new scheduling infrastructure this phase) —
 * started directly via `@temporalio/client`'s `workflow.start`/`.execute`,
 * exactly how `ApprovalWorkflow` itself is started, whether by a future
 * scheduler or (this phase's own tests) directly.
 */
export async function AuditRetentionWorkflow(
  input: AuditRetentionWorkflowInput,
): Promise<AuditRetentionWorkflowResult> {
  return activities.pruneAuditEvents({
    tenantId: input.tenantId,
    retentionWindowMs: input.retentionWindowMs,
  });
}
