-- CreateTable
CREATE TABLE "tenant_catalogs" (
    "tenantId" TEXT NOT NULL,
    "features" JSONB NOT NULL DEFAULT '{}',
    "packs" JSONB NOT NULL DEFAULT '[]',
    "model" JSONB,
    "updatedBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenant_catalogs_pkey" PRIMARY KEY ("tenantId")
);

-- AddForeignKey
ALTER TABLE "tenant_catalogs" ADD CONSTRAINT "tenant_catalogs_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;
