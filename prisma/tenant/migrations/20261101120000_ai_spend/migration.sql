-- AI spend tracker and secrets-guard setting (DOOR). Additive: three new tables.
--
-- Rollback (after rolling back the code that uses them):
--   DROP TABLE "ai_usage_daily"; DROP TABLE "ai_usage_batches"; DROP TABLE "ai_spend_settings";

-- CreateTable
CREATE TABLE "ai_usage_daily" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "day" DATE NOT NULL,
    "toolId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "model" TEXT NOT NULL,
    "requests" INTEGER NOT NULL DEFAULT 0,
    "inputTokens" BIGINT NOT NULL DEFAULT 0,
    "outputTokens" BIGINT NOT NULL DEFAULT 0,
    "costMicros" BIGINT NOT NULL DEFAULT 0,

    CONSTRAINT "ai_usage_daily_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_usage_batches" (
    "hostId" TEXT NOT NULL,
    "batchId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_usage_batches_pkey" PRIMARY KEY ("hostId","batchId")
);

-- CreateTable
CREATE TABLE "ai_spend_settings" (
    "id" TEXT NOT NULL DEFAULT 'default',
    "monthlyBudgetMicros" BIGINT,
    "monthlyCapMicros" BIGINT,
    "secretsMode" TEXT NOT NULL DEFAULT 'mask',
    "capScope" TEXT NOT NULL DEFAULT 'owner',
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "updatedBy" TEXT,

    CONSTRAINT "ai_spend_settings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ai_usage_daily_day_idx" ON "ai_usage_daily"("day");

-- CreateIndex
CREATE UNIQUE INDEX "ai_usage_daily_hostId_day_toolId_provider_model_key" ON "ai_usage_daily"("hostId", "day", "toolId", "provider", "model");

-- AddForeignKey
ALTER TABLE "ai_usage_daily" ADD CONSTRAINT "ai_usage_daily_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
