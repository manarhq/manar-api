-- Release 2026-11-11 (brief §3.4): persist the risk *breakdown* behind an
-- ApprovalRequest so a human reviewer sees why approval was required, with
-- deterministic factors and AI signals separately attributed.
--
-- Additive and nullable on purpose. Rows written before this migration
-- genuinely do not carry these facts, and a reader must render them as
-- "not recorded" rather than as zero -- see the column doc comments in
-- prisma/tenant.prisma. `riskReasonCodes` defaults to an empty array so
-- consumers can iterate it unconditionally; an empty array on a
-- pre-migration row still means "not recorded", which is why the three
-- score columns beside it stay NULL rather than 0.

-- AlterTable
ALTER TABLE "approval_requests" ADD COLUMN     "aiAdvisoryScore" INTEGER,
ADD COLUMN     "deterministicRiskScore" INTEGER,
ADD COLUMN     "riskReasonCodes" JSONB NOT NULL DEFAULT '[]',
ADD COLUMN     "taskRiskCeiling" INTEGER;

-- Why approval was required. Persisted rather than derived: a matched
-- ALLOW rule also records a policyVersionId, so "policyVersionId IS NULL"
-- is not equivalent to "the risk ceiling was the cause".
ALTER TABLE "approval_requests" ADD COLUMN "requiredReason" TEXT;

-- Release 2026-11-11: audit chain verification is now keyset-paginated by
-- `sequence`. Without this index each batch sorts the whole table -- memory
-- is bounded but work is not. Retention pruning scans the same column.
CREATE INDEX "audit_events_sequence_idx" ON "audit_events"("sequence");
