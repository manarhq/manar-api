-- Rule offer after the 3rd identical approval (5 Nov 2026, decision 37). Additive.
-- Rollback (after rolling back the code): drop the table and the two columns.
ALTER TABLE "approval_allow_grants"
  ADD COLUMN "origin" TEXT NOT NULL DEFAULT 'approval',
  ADD COLUMN "resourcePattern" TEXT;

CREATE TABLE "host_rule_offers" (
  "id" TEXT NOT NULL,
  "hostId" TEXT NOT NULL,
  "toolId" TEXT NOT NULL,
  "actionId" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "host_rule_offers_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "host_rule_offers_hostId_toolId_actionId_scope_key"
  ON "host_rule_offers"("hostId", "toolId", "actionId", "scope");
CREATE INDEX "host_approvals_hostId_toolId_actionId_status_decidedAt_idx"
  ON "host_approvals"("hostId", "toolId", "actionId", "status", "decidedAt");
