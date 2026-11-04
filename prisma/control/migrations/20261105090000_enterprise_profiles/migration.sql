-- CreateEnum
CREATE TYPE "EnterpriseSector" AS ENUM ('ENTERPRISE', 'GOVERNMENT');

-- CreateTable
CREATE TABLE "enterprise_profiles" (
    "tenantId" TEXT NOT NULL,
    "sector" "EnterpriseSector" NOT NULL,
    "publicSlug" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "enterprise_profiles_pkey" PRIMARY KEY ("tenantId")
);

-- CreateIndex
CREATE UNIQUE INDEX "enterprise_profiles_publicSlug_key" ON "enterprise_profiles"("publicSlug");

