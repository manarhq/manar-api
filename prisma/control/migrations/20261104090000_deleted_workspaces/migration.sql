-- A tombstone per deleted workspace, so a device of a deleted personal account is told it was
-- removed (410 device_removed) after the workspace database is gone. Additive.
--
-- Rollback (after rolling back the code): DROP TABLE "deleted_workspaces";

CREATE TABLE "deleted_workspaces" (
    "slug" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "deletedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "deleted_workspaces_pkey" PRIMARY KEY ("slug")
);
