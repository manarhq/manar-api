-- Approval history and revoke (3 Nov 2026). Additive: one enum value per status enum, nullable
-- columns, and an `effect` on allow grants so a revoked-after-use approval can block the action.
--
-- Rollback (after rolling back the code): drop the added columns; enum values cannot be dropped
-- in PostgreSQL and are harmless to old code that never writes them (no row may hold REVOKED).

ALTER TYPE "ApprovalStatus" ADD VALUE IF NOT EXISTS 'REVOKED';
ALTER TYPE "HostApprovalStatus" ADD VALUE IF NOT EXISTS 'REVOKED';

ALTER TABLE "approval_requests"
  ADD COLUMN "releasedAt" TIMESTAMP(3),
  ADD COLUMN "revokedAt" TIMESTAMP(3),
  ADD COLUMN "revokedBy" TEXT,
  ADD COLUMN "revokeNote" TEXT,
  ADD COLUMN "usedBeforeRevoke" BOOLEAN,
  ADD COLUMN "endReason" TEXT;

ALTER TABLE "host_approvals"
  ADD COLUMN "usedAt" TIMESTAMP(3),
  ADD COLUMN "revokedAt" TIMESTAMP(3),
  ADD COLUMN "revokedBy" TEXT,
  ADD COLUMN "revokeNote" TEXT,
  ADD COLUMN "usedBeforeRevoke" BOOLEAN,
  ADD COLUMN "endReason" TEXT;

ALTER TABLE "approval_allow_grants" ADD COLUMN "effect" TEXT NOT NULL DEFAULT 'ALLOW';

CREATE INDEX "host_approvals_createdAt_id_idx" ON "host_approvals"("createdAt", "id");
CREATE INDEX "approval_allow_grants_sourceId_idx" ON "approval_allow_grants"("sourceId");

