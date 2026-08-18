-- CreateEnum
CREATE TYPE "PolicyVersionStatus" AS ENUM ('DRAFT', 'PUBLISHED');

-- CreateTable
CREATE TABLE "policies" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "policies_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "policy_versions" (
    "id" TEXT NOT NULL,
    "policyId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "status" "PolicyVersionStatus" NOT NULL DEFAULT 'DRAFT',
    "content" JSONB NOT NULL,
    "contentHash" TEXT NOT NULL,
    "authorId" TEXT NOT NULL,
    "reason" TEXT,
    "previousVersionId" TEXT,
    "publishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "policy_versions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "policies_name_key" ON "policies"("name");

-- CreateIndex
CREATE UNIQUE INDEX "policy_versions_policyId_version_key" ON "policy_versions"("policyId", "version");

-- AddForeignKey
ALTER TABLE "policy_versions" ADD CONSTRAINT "policy_versions_policyId_fkey" FOREIGN KEY ("policyId") REFERENCES "policies"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "policy_versions" ADD CONSTRAINT "policy_versions_authorId_fkey" FOREIGN KEY ("authorId") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "policy_versions" ADD CONSTRAINT "policy_versions_previousVersionId_fkey" FOREIGN KEY ("previousVersionId") REFERENCES "policy_versions"("id") ON DELETE SET NULL ON UPDATE CASCADE;
