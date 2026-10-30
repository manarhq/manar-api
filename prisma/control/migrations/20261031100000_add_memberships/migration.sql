-- AlterEnum
ALTER TYPE "TenantStatus" ADD VALUE IF NOT EXISTS 'QUEUED';
ALTER TYPE "TenantStatus" ADD VALUE IF NOT EXISTS 'FAILED';

-- CreateEnum
CREATE TYPE "TenantKind" AS ENUM ('PERSONAL', 'COMPANY', 'SAMPLE');
CREATE TYPE "MembershipStatus" AS ENUM ('ACTIVE', 'PENDING', 'REMOVED');
CREATE TYPE "MembershipRole" AS ENUM ('TENANT_OWNER', 'SECURITY_ADMIN', 'AI_GOVERNANCE_MANAGER', 'SOC_OPERATOR', 'APPROVER', 'AUDITOR', 'DEVELOPER', 'READ_ONLY');

-- AlterTable
ALTER TABLE "tenants" ADD COLUMN "kind" "TenantKind" NOT NULL DEFAULT 'COMPANY',
ADD COLUMN "ownerSubject" TEXT,
ADD COLUMN "ownerIssuer" TEXT,
ADD COLUMN "provisionAttempts" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN "nextProvisionAt" TIMESTAMP(3),
ADD COLUMN "entraTenantId" TEXT;

-- One personal workspace per subject, one company workspace per Entra tenant.
CREATE UNIQUE INDEX "tenants_personal_owner_key" ON "tenants"("ownerIssuer", "ownerSubject") WHERE "kind" = 'PERSONAL';
CREATE UNIQUE INDEX "tenants_company_entra_key" ON "tenants"("entraTenantId") WHERE "kind" = 'COMPANY' AND "entraTenantId" IS NOT NULL;

-- CreateTable
CREATE TABLE "memberships" (
    "id" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "role" "MembershipRole" NOT NULL,
    "extraRoles" "MembershipRole"[] DEFAULT ARRAY[]::"MembershipRole"[],
    "status" "MembershipStatus" NOT NULL DEFAULT 'PENDING',
    "email" TEXT,
    "displayName" TEXT,
    "grantedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "memberships_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "memberships_issuer_subject_tenantId_key" ON "memberships"("issuer", "subject", "tenantId");
CREATE INDEX "memberships_tenantId_status_idx" ON "memberships"("tenantId", "status");
CREATE INDEX "memberships_issuer_subject_idx" ON "memberships"("issuer", "subject");

ALTER TABLE "memberships" ADD CONSTRAINT "memberships_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;
