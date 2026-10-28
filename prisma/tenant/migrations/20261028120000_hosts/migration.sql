-- Hosts (R2 F2a, docs/hosts.md): org units, host groups, install keys, hosts, host
-- certificates and approval rules. Additive: new enums and tables only.
--
-- Rollback: DROP TABLE "host_approval_rules", "host_certificates", "hosts", "install_keys",
--   "host_groups", "org_units"; DROP TYPE "HostKeyType", "HostStatus", "OrgUnitSource";

-- CreateEnum
CREATE TYPE "OrgUnitSource" AS ENUM ('MANUAL', 'ENTRA', 'AD');

-- CreateEnum
CREATE TYPE "HostStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'REVOKED');

-- CreateEnum
CREATE TYPE "HostKeyType" AS ENUM ('TPM', 'SOFTWARE');

-- CreateTable
CREATE TABLE "org_units" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "parentId" TEXT,
    "externalId" TEXT,
    "source" "OrgUnitSource" NOT NULL DEFAULT 'MANUAL',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "org_units_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_groups" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "orgUnitId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "host_groups_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "install_keys" (
    "id" TEXT NOT NULL,
    "hostGroupId" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "allowedCidrs" TEXT[],
    "maxUses" INTEGER,
    "uses" INTEGER NOT NULL DEFAULT 0,
    "expiresAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "install_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "hosts" (
    "id" TEXT NOT NULL,
    "hostGroupId" TEXT NOT NULL,
    "machineId" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "os" TEXT NOT NULL,
    "keyType" "HostKeyType" NOT NULL,
    "status" "HostStatus" NOT NULL DEFAULT 'PENDING',
    "approvedBy" TEXT,
    "approvedAt" TIMESTAMP(3),
    "lastSeenAt" TIMESTAMP(3),
    "registeredFromIp" TEXT NOT NULL,
    "keyFingerprint" TEXT NOT NULL,
    "pendingKeyFingerprint" TEXT,
    "pendingHostGroupId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "hosts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_certificates" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "notBefore" TIMESTAMP(3) NOT NULL,
    "notAfter" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "caRevokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "host_certificates_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "host_approval_rules" (
    "id" TEXT NOT NULL,
    "hostGroupId" TEXT,
    "hostnamePattern" TEXT,
    "cidrs" TEXT[],
    "requireTpm" BOOLEAN NOT NULL DEFAULT false,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "host_approval_rules_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "org_units_externalId_key" ON "org_units"("externalId");

-- CreateIndex
CREATE INDEX "org_units_parentId_idx" ON "org_units"("parentId");

-- CreateIndex
CREATE UNIQUE INDEX "host_groups_name_key" ON "host_groups"("name");

-- CreateIndex
CREATE UNIQUE INDEX "install_keys_keyHash_key" ON "install_keys"("keyHash");

-- CreateIndex
CREATE INDEX "install_keys_hostGroupId_idx" ON "install_keys"("hostGroupId");

-- CreateIndex
CREATE INDEX "hosts_hostGroupId_idx" ON "hosts"("hostGroupId");

-- CreateIndex
CREATE INDEX "hosts_status_idx" ON "hosts"("status");

-- CreateIndex
CREATE UNIQUE INDEX "hosts_machineId_key" ON "hosts"("machineId");

-- CreateIndex
CREATE UNIQUE INDEX "host_certificates_serialNumber_key" ON "host_certificates"("serialNumber");

-- CreateIndex
CREATE INDEX "host_certificates_hostId_idx" ON "host_certificates"("hostId");

-- AddForeignKey
ALTER TABLE "org_units" ADD CONSTRAINT "org_units_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "org_units"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_groups" ADD CONSTRAINT "host_groups_orgUnitId_fkey" FOREIGN KEY ("orgUnitId") REFERENCES "org_units"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "install_keys" ADD CONSTRAINT "install_keys_hostGroupId_fkey" FOREIGN KEY ("hostGroupId") REFERENCES "host_groups"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "hosts" ADD CONSTRAINT "hosts_hostGroupId_fkey" FOREIGN KEY ("hostGroupId") REFERENCES "host_groups"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_certificates" ADD CONSTRAINT "host_certificates_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_approval_rules" ADD CONSTRAINT "host_approval_rules_hostGroupId_fkey" FOREIGN KEY ("hostGroupId") REFERENCES "host_groups"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

