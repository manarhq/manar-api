-- The real path an 8-hour grant was made for, when the approval was for a link (6 Nov 2026). Additive.
-- Rollback (after rolling back the code): drop the column.
ALTER TABLE "approval_allow_grants" ADD COLUMN "resolvedPath" TEXT;
