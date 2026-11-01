-- Weekly AI report card and its public shares (features track). Additive.
-- Rollback: DROP TABLE "report_shares"; DROP TABLE "weekly_report_cards";

CREATE TABLE "weekly_report_cards" (
    "tenantId" TEXT NOT NULL,
    "weekEnd" TIMESTAMP(3) NOT NULL,
    "data" JSONB NOT NULL,
    "computedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "weekly_report_cards_pkey" PRIMARY KEY ("tenantId","weekEnd")
);

CREATE TABLE "report_shares" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "totals" JSONB NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "report_shares_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "report_shares_tenantId_idx" ON "report_shares"("tenantId");
