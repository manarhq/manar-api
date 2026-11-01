-- Secrets track 2: the workspace's secret blocking mode. Additive: one new table.
--
-- Rollback (after rolling back the code): DROP TABLE "secret_settings";

-- CreateTable
CREATE TABLE "secret_settings" (
    "id" TEXT NOT NULL DEFAULT 'default',
    "blockMode" TEXT NOT NULL DEFAULT 'keys',
    "updatedBy" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "secret_settings_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "secret_settings_blockMode_check" CHECK ("blockMode" IN ('off', 'keys', 'all'))
);
