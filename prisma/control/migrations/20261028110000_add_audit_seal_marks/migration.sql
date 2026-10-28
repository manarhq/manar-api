-- Audit SEAL marks (docs/audit-chain.md, ADR-0014): each tenant's newest signed checkpoint,
-- kept outside the tenant database, plus the incremental-verification watermark.
--
-- Additive. Rollback: DROP TABLE "audit_seal_marks";

-- CreateTable
CREATE TABLE "audit_seal_marks" (
    "tenantId" TEXT NOT NULL,
    "sealSeq" BIGINT NOT NULL,
    "sealHash" TEXT NOT NULL,
    "verifiedSeq" BIGINT,
    "verifiedHash" TEXT,
    "verifiedHeads" JSONB,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "audit_seal_marks_pkey" PRIMARY KEY ("tenantId")
);
