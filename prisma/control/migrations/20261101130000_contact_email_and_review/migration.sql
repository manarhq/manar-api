ALTER TABLE "tenants" ADD COLUMN "autoJoinSeatCap" INTEGER NOT NULL DEFAULT 25;

ALTER TABLE "launch_offer_claims"
  ADD COLUMN "emailDomain" TEXT,
  ADD COLUMN "ipHash" TEXT,
  ADD COLUMN "ekHash" TEXT;
CREATE UNIQUE INDEX "launch_offer_claims_ekHash_key" ON "launch_offer_claims"("ekHash");
CREATE INDEX "launch_offer_claims_claimedAt_idx" ON "launch_offer_claims"("claimedAt");

CREATE TABLE "contact_emails" (
  "issuer" TEXT NOT NULL,
  "subject" TEXT NOT NULL,
  "email" TEXT,
  "verifiedAt" TIMESTAMP(3),
  "idp" TEXT,
  "pendingEmail" TEXT,
  "codeHash" TEXT,
  "codeExpiresAt" TIMESTAMP(3),
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "sendsInWindow" INTEGER NOT NULL DEFAULT 0,
  "windowStartedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "contact_emails_pkey" PRIMARY KEY ("issuer", "subject")
);
