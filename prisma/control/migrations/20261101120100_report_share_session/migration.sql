-- A report link can share one redacted agent session (insight track). Additive: one nullable column.
--
-- Rollback (after rolling back the code that uses it): ALTER TABLE "report_shares" DROP COLUMN "session";

-- AlterTable
ALTER TABLE "report_shares" ADD COLUMN "session" JSONB;
