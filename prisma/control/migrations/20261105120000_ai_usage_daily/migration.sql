-- CreateTable
CREATE TABLE "ai_usage_daily" (
    "day" DATE NOT NULL,
    "tenantId" TEXT NOT NULL,
    "feature" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "model" TEXT NOT NULL,
    "calls" INTEGER NOT NULL DEFAULT 0,
    "errors" INTEGER NOT NULL DEFAULT 0,
    "inputTokens" BIGINT NOT NULL DEFAULT 0,
    "outputTokens" BIGINT NOT NULL DEFAULT 0,
    "costMicros" BIGINT NOT NULL DEFAULT 0,
    "unpricedCalls" INTEGER NOT NULL DEFAULT 0,
    "latencyMsSum" BIGINT NOT NULL DEFAULT 0,
    "latencyBuckets" INTEGER[],
    "priceVersion" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ai_usage_daily_pkey" PRIMARY KEY ("day","tenantId","feature","provider","model")
);

-- CreateIndex
CREATE INDEX "ai_usage_daily_tenantId_day_idx" ON "ai_usage_daily"("tenantId", "day");
