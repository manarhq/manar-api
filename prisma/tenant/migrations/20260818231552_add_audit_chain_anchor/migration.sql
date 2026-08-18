-- CreateTable
CREATE TABLE "audit_chain_anchors" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "anchorHash" TEXT NOT NULL,
    "anchoredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "eventsPrunedCount" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_chain_anchors_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "audit_chain_anchors_tenantId_idx" ON "audit_chain_anchors"("tenantId");
