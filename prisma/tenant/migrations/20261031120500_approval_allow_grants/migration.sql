-- "Approve for 8 hours" grants and host-opened approvals (spec 4.6). Additive: two tables, one enum.
--
-- Rollback (after rolling back the code): DROP TABLE "approval_allow_grants"; DROP TABLE "host_approvals";
--   DROP TYPE "HostApprovalStatus";

-- CreateEnum
CREATE TYPE "HostApprovalStatus" AS ENUM ('PENDING', 'APPROVED', 'DENIED', 'EXPIRED');

-- CreateTable
CREATE TABLE "approval_allow_grants" (
    "id" TEXT NOT NULL,
    "hostId" TEXT,
    "agentId" TEXT,
    "toolId" TEXT NOT NULL,
    "actionId" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "sourceId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "useCount" INTEGER NOT NULL DEFAULT 0,
    "lastUsedAt" TIMESTAMP(3),

    CONSTRAINT "approval_allow_grants_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "approval_allow_grants_one_scope" CHECK (("hostId" IS NULL) <> ("agentId" IS NULL))
);

-- CreateTable
CREATE TABLE "host_approvals" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "toolId" TEXT NOT NULL,
    "actionId" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "highRisk" BOOLEAN NOT NULL DEFAULT false,
    "status" "HostApprovalStatus" NOT NULL DEFAULT 'PENDING',
    "decision" TEXT,
    "decidedBy" TEXT,
    "decidedVia" TEXT,
    "decidedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "host_approvals_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "approval_allow_grants_hostId_toolId_actionId_expiresAt_idx" ON "approval_allow_grants"("hostId", "toolId", "actionId", "expiresAt");

-- CreateIndex
CREATE INDEX "approval_allow_grants_agentId_toolId_actionId_expiresAt_idx" ON "approval_allow_grants"("agentId", "toolId", "actionId", "expiresAt");

-- CreateIndex
CREATE INDEX "host_approvals_hostId_status_expiresAt_idx" ON "host_approvals"("hostId", "status", "expiresAt");

-- AddForeignKey
ALTER TABLE "approval_allow_grants" ADD CONSTRAINT "approval_allow_grants_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "approval_allow_grants" ADD CONSTRAINT "approval_allow_grants_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "host_approvals" ADD CONSTRAINT "host_approvals_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
