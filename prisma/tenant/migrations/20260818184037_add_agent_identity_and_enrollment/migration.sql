-- CreateEnum
CREATE TYPE "AgentStatus" AS ENUM ('PENDING_ENROLLMENT', 'ACTIVE', 'REVOKED', 'KILLED');

-- CreateTable
CREATE TABLE "agents" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "status" "AgentStatus" NOT NULL DEFAULT 'PENDING_ENROLLMENT',
    "capabilities" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT NOT NULL,

    CONSTRAINT "agents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_groups" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_groups_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_group_memberships" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "groupId" TEXT NOT NULL,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_group_memberships_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_enrollment_tokens" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT NOT NULL,

    CONSTRAINT "agent_enrollment_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "agent_certificates" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "notBefore" TIMESTAMP(3) NOT NULL,
    "notAfter" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revocationReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_certificates_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "agents_slug_key" ON "agents"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "agents_identifier_key" ON "agents"("identifier");

-- CreateIndex
CREATE UNIQUE INDEX "agent_groups_name_key" ON "agent_groups"("name");

-- CreateIndex
CREATE UNIQUE INDEX "agent_group_memberships_agentId_groupId_key" ON "agent_group_memberships"("agentId", "groupId");

-- CreateIndex
CREATE UNIQUE INDEX "agent_enrollment_tokens_tokenHash_key" ON "agent_enrollment_tokens"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "agent_certificates_serialNumber_key" ON "agent_certificates"("serialNumber");

-- AddForeignKey
ALTER TABLE "agents" ADD CONSTRAINT "agents_createdBy_fkey" FOREIGN KEY ("createdBy") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_group_memberships" ADD CONSTRAINT "agent_group_memberships_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_group_memberships" ADD CONSTRAINT "agent_group_memberships_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "agent_groups"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_enrollment_tokens" ADD CONSTRAINT "agent_enrollment_tokens_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_enrollment_tokens" ADD CONSTRAINT "agent_enrollment_tokens_createdBy_fkey" FOREIGN KEY ("createdBy") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "agent_certificates" ADD CONSTRAINT "agent_certificates_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
