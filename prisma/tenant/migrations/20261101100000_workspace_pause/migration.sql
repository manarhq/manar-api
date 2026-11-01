-- "Pause all AI": one row per workspace. Additive.
-- Rollback (after rolling back the code): DROP TABLE "workspace_pause";

-- CreateTable
CREATE TABLE "workspace_pause" (
    "id" TEXT NOT NULL DEFAULT 'workspace',
    "paused" BOOLEAN NOT NULL DEFAULT false,
    "pausedBy" TEXT,
    "pausedByRole" TEXT,
    "pausedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "workspace_pause_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "workspace_pause_single" CHECK ("id" = 'workspace')
);

-- Deploy order: run this tenant migration BEFORE the new code. If the table is missing the code denies
-- every protected call with enforcement_dependency_unavailable (fail closed), so a wrong order stops AI
-- work instead of leaving it unpaused.
