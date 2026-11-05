-- Newest FULL audit-chain verification result per tenant.
-- Rollback: DROP TABLE "audit_full_verifications";
CREATE TABLE "audit_full_verifications" (
    "tenantId" TEXT NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "result" TEXT,
    "brokenAt" TEXT,
    "lastPassedAt" TIMESTAMP(3),
    "durationMs" INTEGER,
    "claimedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "audit_full_verifications_pkey" PRIMARY KEY ("tenantId")
);
