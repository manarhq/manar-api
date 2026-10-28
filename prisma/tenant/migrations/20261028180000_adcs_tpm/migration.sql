-- AD CS enrolment, AD OU mapping, TPM attestation and the approval-rule guard (R2 F2b,
-- docs/hosts.md). Additive: new columns with defaults and new tables only.
--
-- Rollback: DROP TABLE "tpm_challenges", "tpm_trust_roots", "ad_ou_rules", "adcs_settings",
--   "adcs_trusted_cas"; ALTER TABLE "host_approval_rules" DROP COLUMN "adOuDn", DROP COLUMN
--   "requireAdcs"; ALTER TABLE "hosts" DROP COLUMN "adDn", DROP COLUMN "adDnCheckedAt", DROP
--   COLUMN "adcsDnsName", DROP COLUMN "enrolmentMethod", DROP COLUMN "tpmEkFingerprint", DROP
--   COLUMN "tpmVerified". Rows written by F2b (ADCS hosts, trusted CAs, OU rules) are lost.


-- AlterTable
ALTER TABLE "hosts" ADD COLUMN     "adDn" TEXT,
ADD COLUMN     "adDnCheckedAt" TIMESTAMP(3),
ADD COLUMN     "adcsDnsName" TEXT,
ADD COLUMN     "enrolmentMethod" TEXT NOT NULL DEFAULT 'INSTALL_KEY',
ADD COLUMN     "tpmEkFingerprint" TEXT,
ADD COLUMN     "tpmVerified" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "host_approval_rules" ADD COLUMN     "adOuDn" TEXT,
ADD COLUMN     "requireAdcs" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "adcs_trusted_cas" (
    "id" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "certPem" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "notAfter" TIMESTAMP(3) NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "adcs_trusted_cas_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "adcs_settings" (
    "id" TEXT NOT NULL DEFAULT 'default',
    "defaultHostGroupId" TEXT NOT NULL,
    "ldapsUrl" TEXT,
    "baseDn" TEXT,
    "bindDn" TEXT,
    "serverCaPem" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "adcs_settings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ad_ou_rules" (
    "id" TEXT NOT NULL,
    "ouDn" TEXT NOT NULL,
    "ouDnKey" TEXT NOT NULL,
    "hostGroupId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ad_ou_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tpm_trust_roots" (
    "id" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "certPem" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "notAfter" TIMESTAMP(3) NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tpm_trust_roots_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tpm_challenges" (
    "id" TEXT NOT NULL,
    "machineId" TEXT NOT NULL,
    "keyFingerprint" TEXT NOT NULL,
    "ekFingerprint" TEXT NOT NULL,
    "secretHash" TEXT NOT NULL,
    "attemptsLeft" INTEGER NOT NULL DEFAULT 3,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tpm_challenges_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "adcs_trusted_cas_fingerprint_key" ON "adcs_trusted_cas"("fingerprint");

-- CreateIndex
CREATE UNIQUE INDEX "ad_ou_rules_ouDnKey_key" ON "ad_ou_rules"("ouDnKey");

-- CreateIndex
CREATE INDEX "ad_ou_rules_hostGroupId_idx" ON "ad_ou_rules"("hostGroupId");

-- CreateIndex
CREATE UNIQUE INDEX "tpm_trust_roots_fingerprint_key" ON "tpm_trust_roots"("fingerprint");

-- CreateIndex
CREATE INDEX "tpm_challenges_expiresAt_idx" ON "tpm_challenges"("expiresAt");

-- AddForeignKey
ALTER TABLE "adcs_settings" ADD CONSTRAINT "adcs_settings_defaultHostGroupId_fkey" FOREIGN KEY ("defaultHostGroupId") REFERENCES "host_groups"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ad_ou_rules" ADD CONSTRAINT "ad_ou_rules_hostGroupId_fkey" FOREIGN KEY ("hostGroupId") REFERENCES "host_groups"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

