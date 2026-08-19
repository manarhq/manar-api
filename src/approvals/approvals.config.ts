import { z } from 'zod';

/**
 * Phase 8 (Approval Engine) config — the shared secret an `AuthorizationGrant`
 * (see docs/approvals.md) is signed/verified with, and the two TTLs the
 * design spec explicitly asks to "pick and document a value" for. Read by
 * both the main HTTP process (signs grants inside the worker's Activities —
 * see `src/temporal/worker-app.module.ts` — and verifies them in
 * `POST /agent/v1/tools/invoke`) and the separate worker process, so both
 * must be configured with the *same* `APPROVAL_GRANT_SIGNING_SECRET` or a
 * grant issued by one and verified by the other never validates.
 */
export const ApprovalsConfigSchema = z.object({
  /**
   * HS256 signing secret for `AuthorizationGrant` tokens
   * (`src/approvals/grant-token.util.ts`). No production default — the
   * `.env.example`/`.env` dev value is only ever a placeholder, same
   * posture as this codebase's other dev-only secrets (see
   * `deploy/openbao-init.mjs`'s root token).
   */
  APPROVAL_GRANT_SIGNING_SECRET: z.string().min(16),
  /** How long an issued `AuthorizationGrant` remains usable — short by design (Section 31). Default 5 minutes. */
  APPROVAL_GRANT_TTL_MS: z.coerce.number().int().positive().default(300_000),
  /** How long an `ApprovalRequest` waits for a human `decide` before `ApprovalWorkflow` times it out to `EXPIRED`. Default 30 minutes. */
  APPROVAL_REQUEST_TTL_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(1_800_000),
  /**
   * Security cleanup 1 (Phase 14): `POST /approvals/:id/decide` now
   * synchronously awaits `ApprovalWorkflow`'s actual resolved outcome
   * (`WorkflowHandle.result()`) instead of returning immediately after
   * signaling — see `ApprovalsController.decide`'s doc comment for why.
   * This bounds how long that wait is allowed to take before the HTTP
   * handler gives up and reports a timeout rather than hanging the
   * connection indefinitely: comfortably above `finalizeApprovalDecision`'s
   * own worst-case Activity retry budget (5 attempts, `30s`
   * `startToCloseTimeout` each, exponential backoff between attempts) so a
   * normal decision — even one that needed a retry or two — always
   * resolves well inside this window; a genuine worker outage still fails
   * the HTTP request rather than blocking it forever. Default 2 minutes.
   */
  APPROVAL_DECIDE_RESULT_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .positive()
    .default(120_000),
});

export type ApprovalsConfig = z.infer<typeof ApprovalsConfigSchema>;
