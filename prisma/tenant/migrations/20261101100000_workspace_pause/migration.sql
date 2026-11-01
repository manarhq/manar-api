-- "Pause all AI": one row per workspace. Additive.
-- Rollback (after rolling back the code): DROP TABLE "workspace_pause";

-- CreateTable
CREATE TABLE "workspace_pause" (
    "id" TEXT NOT NULL DEFAULT 'workspace',
    "paused" BOOLEAN NOT NULL DEFAULT false,
    "pausedBy" TEXT,
    "pausedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "workspace_pause_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "workspace_pause_single" CHECK ("id" = 'workspace')
);
