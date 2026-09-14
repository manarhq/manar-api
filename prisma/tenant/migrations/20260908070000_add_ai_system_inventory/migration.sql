
-- CreateEnum
CREATE TYPE "AiSystemLifecycleState" AS ENUM ('DRAFT', 'REVIEW', 'ACTIVE', 'SUSPENDED', 'RETIRED');

-- CreateEnum
CREATE TYPE "AiSystemEnvironment" AS ENUM ('DEVELOPMENT', 'STAGING', 'PRODUCTION');

-- AlterTable
ALTER TABLE "incidents" ADD COLUMN     "aiSystemId" TEXT;

-- CreateTable
CREATE TABLE "ai_systems" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "businessPurpose" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "businessUnit" TEXT NOT NULL,
    "environment" "AiSystemEnvironment" NOT NULL,
    "lifecycleState" "AiSystemLifecycleState" NOT NULL DEFAULT 'DRAFT',
    "dataClassification" "DataClassification" NOT NULL DEFAULT 'INTERNAL',
    "declaredProvider" TEXT,
    "declaredModel" TEXT,
    "riskRationale" TEXT NOT NULL,
    "nextReviewDate" TIMESTAMP(3),
    "version" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ai_systems_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_system_versions" (
    "id" TEXT NOT NULL,
    "aiSystemId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "snapshot" JSONB NOT NULL,
    "changeReason" TEXT NOT NULL,
    "changedBy" TEXT NOT NULL,
    "changedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_system_versions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_system_agent_links" (
    "id" TEXT NOT NULL,
    "aiSystemId" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "linkedBy" TEXT NOT NULL,
    "linkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_system_agent_links_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_system_tool_links" (
    "id" TEXT NOT NULL,
    "aiSystemId" TEXT NOT NULL,
    "toolId" TEXT NOT NULL,
    "linkedBy" TEXT NOT NULL,
    "linkedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_system_tool_links_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_system_state_transitions" (
    "id" TEXT NOT NULL,
    "aiSystemId" TEXT NOT NULL,
    "fromState" "AiSystemLifecycleState" NOT NULL,
    "toState" "AiSystemLifecycleState" NOT NULL,
    "reason" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_system_state_transitions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ai_systems_slug_key" ON "ai_systems"("slug");

-- CreateIndex
CREATE INDEX "ai_systems_lifecycleState_idx" ON "ai_systems"("lifecycleState");

-- CreateIndex
CREATE INDEX "ai_systems_environment_idx" ON "ai_systems"("environment");

-- CreateIndex
CREATE INDEX "ai_systems_ownerId_idx" ON "ai_systems"("ownerId");

-- CreateIndex
CREATE INDEX "ai_systems_nextReviewDate_idx" ON "ai_systems"("nextReviewDate");

-- CreateIndex
CREATE INDEX "ai_system_versions_aiSystemId_changedAt_idx" ON "ai_system_versions"("aiSystemId", "changedAt");

-- CreateIndex
CREATE UNIQUE INDEX "ai_system_versions_aiSystemId_version_key" ON "ai_system_versions"("aiSystemId", "version");

-- CreateIndex
CREATE INDEX "ai_system_agent_links_agentId_idx" ON "ai_system_agent_links"("agentId");

-- CreateIndex
CREATE UNIQUE INDEX "ai_system_agent_links_aiSystemId_agentId_key" ON "ai_system_agent_links"("aiSystemId", "agentId");

-- CreateIndex
CREATE INDEX "ai_system_tool_links_toolId_idx" ON "ai_system_tool_links"("toolId");

-- CreateIndex
CREATE UNIQUE INDEX "ai_system_tool_links_aiSystemId_toolId_key" ON "ai_system_tool_links"("aiSystemId", "toolId");

-- CreateIndex
CREATE INDEX "ai_system_state_transitions_aiSystemId_at_idx" ON "ai_system_state_transitions"("aiSystemId", "at");

-- CreateIndex
CREATE INDEX "incidents_aiSystemId_idx" ON "incidents"("aiSystemId");

-- AddForeignKey
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_aiSystemId_fkey" FOREIGN KEY ("aiSystemId") REFERENCES "ai_systems"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_systems" ADD CONSTRAINT "ai_systems_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_systems" ADD CONSTRAINT "ai_systems_createdBy_fkey" FOREIGN KEY ("createdBy") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_versions" ADD CONSTRAINT "ai_system_versions_aiSystemId_fkey" FOREIGN KEY ("aiSystemId") REFERENCES "ai_systems"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_versions" ADD CONSTRAINT "ai_system_versions_changedBy_fkey" FOREIGN KEY ("changedBy") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_agent_links" ADD CONSTRAINT "ai_system_agent_links_aiSystemId_fkey" FOREIGN KEY ("aiSystemId") REFERENCES "ai_systems"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_agent_links" ADD CONSTRAINT "ai_system_agent_links_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_agent_links" ADD CONSTRAINT "ai_system_agent_links_linkedBy_fkey" FOREIGN KEY ("linkedBy") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_tool_links" ADD CONSTRAINT "ai_system_tool_links_aiSystemId_fkey" FOREIGN KEY ("aiSystemId") REFERENCES "ai_systems"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_tool_links" ADD CONSTRAINT "ai_system_tool_links_toolId_fkey" FOREIGN KEY ("toolId") REFERENCES "tools"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_tool_links" ADD CONSTRAINT "ai_system_tool_links_linkedBy_fkey" FOREIGN KEY ("linkedBy") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_state_transitions" ADD CONSTRAINT "ai_system_state_transitions_aiSystemId_fkey" FOREIGN KEY ("aiSystemId") REFERENCES "ai_systems"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_system_state_transitions" ADD CONSTRAINT "ai_system_state_transitions_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

