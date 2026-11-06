-- Where a file approval really points, and whether the device vouched for it (6 Nov 2026). Additive.
-- Rollback (after rolling back the code): drop the two columns.
ALTER TABLE "host_approvals" ADD COLUMN "resolvedPath" TEXT;
ALTER TABLE "host_approvals" ADD COLUMN "pathLinked" BOOLEAN NOT NULL DEFAULT false;
