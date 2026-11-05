-- Nightly full audit-chain verification result per tenant.
-- Rollback: DROP TABLE "audit_full_verifications";
CREATE TABLE "audit_full_verifications" (
    "tenantId" TEXT NOT NULL,
    "verifiedAt" TIMESTAMP(3) NOT NULL,
    "valid" BOOLEAN NOT NULL,
    "brokenAt" TEXT,

    CONSTRAINT "audit_full_verifications_pkey" PRIMARY KEY ("tenantId")
);
