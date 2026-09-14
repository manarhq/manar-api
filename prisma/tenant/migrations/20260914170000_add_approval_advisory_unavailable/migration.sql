-- Phase 1 (ADR-004, CLAUDE.md §12): manar-ai is no longer called from the
-- synchronous authorization decision path. `RiskEngine.score` used to await
-- `AiAdvisoryClient.analyzeRisk` and fold the result in as
-- `max(deterministic, advisory ?? 0)`, which put a language model inside the
-- authorization decision. The decision is now deterministic-only, and the
-- advisory is fetched off the decision path by `ApprovalWorkflow` and attached
-- to the approval for the *human approver* instead.
--
-- That reordering creates a window this column exists to describe: the
-- approval row is written first, with no advisory yet, and enriched later --
-- or never, if manar-ai is down. Without a dedicated flag, "the AI assessed
-- this as low risk" and "the AI never answered" both render as a NULL
-- aiAdvisoryScore, and an approver cannot tell them apart. CLAUDE.md §6
-- requires manar-ai's unavailability to be visible on the record.
--
-- Defaults to TRUE -- absent until proven present. Backfilling existing rows
-- to TRUE is correct rather than lossy: every row written before this
-- migration was created under the old flow, where a NULL aiAdvisoryScore
-- already meant no signal was available (see that column's doc comment in
-- prisma/tenant.prisma). Rows that DO carry a score are corrected to FALSE
-- below, so historical approvals keep reading truthfully.

-- AlterTable
ALTER TABLE "approval_requests" ADD COLUMN     "advisoryUnavailable" BOOLEAN NOT NULL DEFAULT true;

-- Historical rows that genuinely captured an advisory score did have one
-- attached; they must not now claim otherwise.
UPDATE "approval_requests" SET "advisoryUnavailable" = false WHERE "aiAdvisoryScore" IS NOT NULL;
