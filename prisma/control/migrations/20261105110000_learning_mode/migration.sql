-- Learning mode switch per workspace (5 Nov 2026, decision 36). Additive. Rollback: drop the column.
ALTER TABLE "tenants" ADD COLUMN "learningMode" TEXT;
