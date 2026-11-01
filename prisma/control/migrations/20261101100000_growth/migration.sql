-- Growth track: launch offer, public profile, invites, account deletion, digest preferences.
ALTER TABLE "tenants" ADD COLUMN "autoJoinEntra" BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE "memberships"
  ADD COLUMN "weeklyDigest" BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN "timezone" TEXT,
  ADD COLUMN "locale" TEXT,
  ADD COLUMN "digestSentWeek" TEXT;

CREATE TABLE "launch_offer_claims" (
  "id" TEXT NOT NULL,
  "issuer" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "deviceHash" TEXT NOT NULL,
  "stripeSubscriptionId" TEXT,
  "claimedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "launch_offer_claims_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "launch_offer_claims_tenantId_key" ON "launch_offer_claims"("tenantId");
CREATE UNIQUE INDEX "launch_offer_claims_deviceHash_key" ON "launch_offer_claims"("deviceHash");
CREATE UNIQUE INDEX "launch_offer_claims_issuer_subject_key" ON "launch_offer_claims"("issuer", "subject");

CREATE TABLE "public_profiles" (
  "tenantId" TEXT NOT NULL,
  "slug" TEXT NOT NULL,
  "enabled" BOOLEAN NOT NULL DEFAULT false,
  "stats" JSONB,
  "statsAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "public_profiles_pkey" PRIMARY KEY ("tenantId")
);
CREATE UNIQUE INDEX "public_profiles_slug_key" ON "public_profiles"("slug");

CREATE TABLE "workspace_invites" (
  "id" TEXT NOT NULL,
  "tenantId" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "role" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "usedAt" TIMESTAMP(3),
  "usedBy" TEXT,
  "revokedAt" TIMESTAMP(3),
  "createdBy" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "workspace_invites_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "workspace_invites_tenantId_idx" ON "workspace_invites"("tenantId");

CREATE TABLE "account_deletions" (
  "id" TEXT NOT NULL,
  "issuer" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'SCHEDULED',
  "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "executeAfter" TIMESTAMP(3) NOT NULL,
  "doneAt" TIMESTAMP(3),
  "summary" JSONB,
  CONSTRAINT "account_deletions_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "account_deletions_issuer_subject_key" ON "account_deletions"("issuer", "subject");
CREATE INDEX "account_deletions_status_executeAfter_idx" ON "account_deletions"("status", "executeAfter");
