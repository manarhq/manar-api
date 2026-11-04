-- CreateEnum
CREATE TYPE "CreditSource" AS ENUM ('purchase', 'top_up', 'referral', 'promo', 'contract');

-- CreateEnum
CREATE TYPE "UsageKind" AS ENUM ('ai', 'cloud_minute');

-- AlterEnum
ALTER TYPE "EntitlementPlan" ADD VALUE 'trial';

-- AlterEnum
ALTER TYPE "EntitlementStatus" ADD VALUE 'frozen';

-- AlterTable
ALTER TABLE "tenant_entitlements" ADD COLUMN     "committedSeats" INTEGER;

-- CreateTable
CREATE TABLE "credit_wallets" (
    "tenantId" TEXT NOT NULL,
    "capCredits" INTEGER,
    "autoTopUp" BOOLEAN NOT NULL DEFAULT false,
    "topUpPendingAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "credit_wallets_pkey" PRIMARY KEY ("tenantId")
);

-- CreateTable
CREATE TABLE "credit_lots" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "source" "CreditSource" NOT NULL,
    "credits" INTEGER NOT NULL,
    "remaining" INTEGER NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "stripeRef" TEXT,
    "paymentRefs" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "spent" INTEGER NOT NULL DEFAULT 0,
    "revoked" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "credit_lots_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "usage_months" (
    "tenantId" TEXT NOT NULL,
    "month" TEXT NOT NULL,
    "aiUsed" INTEGER NOT NULL DEFAULT 0,
    "minutesUsed" INTEGER NOT NULL DEFAULT 0,
    "creditsSpent" INTEGER NOT NULL DEFAULT 0,
    "topUps" INTEGER NOT NULL DEFAULT 0,
    "alertsSent" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "usage_months_pkey" PRIMARY KEY ("tenantId","month")
);

-- CreateTable
CREATE TABLE "usage_events" (
    "tenantId" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "kind" "UsageKind" NOT NULL,
    "source" TEXT NOT NULL,
    "lotId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "usage_events_pkey" PRIMARY KEY ("tenantId","key")
);

-- CreateTable
CREATE TABLE "active_days" (
    "tenantId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "subjectId" TEXT NOT NULL,
    "day" DATE NOT NULL,

    CONSTRAINT "active_days_pkey" PRIMARY KEY ("tenantId","kind","subjectId","day")
);

-- CreateTable
CREATE TABLE "meter_reports" (
    "identifier" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "meter" TEXT NOT NULL,
    "month" TEXT NOT NULL,
    "value" INTEGER NOT NULL,
    "reportedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "meter_reports_pkey" PRIMARY KEY ("identifier")
);

-- CreateTable
CREATE TABLE "trial_claims" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "emailHash" TEXT,
    "emailDomain" TEXT,
    "deviceHash" TEXT,
    "ekHash" TEXT,
    "ipHash" TEXT,
    "cardFingerprint" TEXT,
    "remindersSent" INTEGER[] DEFAULT ARRAY[]::INTEGER[],
    "claimedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "trial_claims_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "credit_lots_stripeRef_key" ON "credit_lots"("stripeRef");

-- CreateIndex
CREATE INDEX "credit_lots_tenantId_expiresAt_idx" ON "credit_lots"("tenantId", "expiresAt");

-- CreateIndex
CREATE INDEX "credit_lots_paymentRefs_idx" ON "credit_lots" USING GIN ("paymentRefs");

-- CreateIndex
CREATE INDEX "usage_events_createdAt_idx" ON "usage_events"("createdAt");

-- CreateIndex
CREATE INDEX "active_days_tenantId_day_idx" ON "active_days"("tenantId", "day");

-- CreateIndex
CREATE INDEX "meter_reports_tenantId_meter_month_idx" ON "meter_reports"("tenantId", "meter", "month");

-- CreateIndex
CREATE INDEX "meter_reports_reportedAt_idx" ON "meter_reports"("reportedAt");

-- CreateIndex
CREATE UNIQUE INDEX "trial_claims_tenantId_key" ON "trial_claims"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "trial_claims_emailHash_key" ON "trial_claims"("emailHash");

-- CreateIndex
CREATE UNIQUE INDEX "trial_claims_deviceHash_key" ON "trial_claims"("deviceHash");

-- CreateIndex
CREATE UNIQUE INDEX "trial_claims_ekHash_key" ON "trial_claims"("ekHash");

-- CreateIndex
CREATE UNIQUE INDEX "trial_claims_cardFingerprint_key" ON "trial_claims"("cardFingerprint");

-- CreateIndex
CREATE INDEX "trial_claims_claimedAt_idx" ON "trial_claims"("claimedAt");

-- CreateIndex
CREATE UNIQUE INDEX "trial_claims_issuer_subject_kind_key" ON "trial_claims"("issuer", "subject", "kind");

-- A lot never goes below zero or above what was bought.
ALTER TABLE "credit_lots" ADD CONSTRAINT "credit_lots_remaining_check"
  CHECK ("remaining" >= 0 AND "remaining" <= "credits" AND "spent" >= 0 AND "revoked" >= 0);

-- The launch offer is retired: whoever claimed it has had their free period, so the 14-day trial
-- is not given again to the same person, device or TPM key. Same hash inputs as the launch offer.
INSERT INTO "trial_claims" ("id", "tenantId", "kind", "issuer", "subject", "emailDomain", "deviceHash", "ekHash", "ipHash", "claimedAt")
SELECT "id", "tenantId", 'personal', "issuer", "subject", "emailDomain", "deviceHash", "ekHash", "ipHash", "claimedAt"
FROM "launch_offer_claims"
ON CONFLICT DO NOTHING;
