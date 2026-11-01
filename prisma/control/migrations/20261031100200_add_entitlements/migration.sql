-- Per-tenant plan and Stripe ids, plus processed Stripe event ids (docs/billing.md).
--
-- Additive. Rollback: DROP TABLE "stripe_events"; DROP TABLE "tenant_entitlements";
-- DROP TYPE "EntitlementStatus"; DROP TYPE "EntitlementPlan";

-- CreateEnum
CREATE TYPE "EntitlementPlan" AS ENUM ('free', 'pro', 'company_trial', 'company', 'enterprise');

-- CreateEnum
CREATE TYPE "EntitlementStatus" AS ENUM ('active', 'past_due', 'read_only');

-- CreateTable
CREATE TABLE "tenant_entitlements" (
    "tenantId" TEXT NOT NULL,
    "plan" "EntitlementPlan" NOT NULL DEFAULT 'free',
    "status" "EntitlementStatus" NOT NULL DEFAULT 'active',
    "trialEndsAt" TIMESTAMP(3),
    "stripeCustomerId" TEXT,
    "stripeSubscriptionId" TEXT,
    "billingInterval" TEXT,
    "lastStripeEventAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenant_entitlements_pkey" PRIMARY KEY ("tenantId")
);

-- CreateTable
CREATE TABLE "stripe_events" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "processedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "stripe_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "tenant_entitlements_stripeCustomerId_key" ON "tenant_entitlements"("stripeCustomerId");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_entitlements_stripeSubscriptionId_key" ON "tenant_entitlements"("stripeSubscriptionId");

-- AddForeignKey
ALTER TABLE "tenant_entitlements" ADD CONSTRAINT "tenant_entitlements_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;
