-- Cloud agents (docs/cloud-agents.md): agent kind and the OAuth binding of a CLOUD agent.
--
-- Additive: two enum types, one column with a default and one table. API processes on the
-- previous client keep working (they never read the new column or table).
--
-- Rollback (after rolling back the code that reads them):
--   DROP TABLE "cloud_agent_bindings";
--   ALTER TABLE "agents" DROP COLUMN "kind";
--   DROP TYPE "CloudAgentPlatform"; DROP TYPE "AgentKind";

-- CreateEnum
CREATE TYPE "AgentKind" AS ENUM ('WORKLOAD', 'CLOUD');

-- CreateEnum
CREATE TYPE "CloudAgentPlatform" AS ENUM ('COPILOT_STUDIO', 'CHATGPT');

-- AlterTable
ALTER TABLE "agents" ADD COLUMN     "kind" "AgentKind" NOT NULL DEFAULT 'WORKLOAD';

-- CreateTable
CREATE TABLE "cloud_agent_bindings" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "platform" "CloudAgentPlatform" NOT NULL,
    "oauthClientId" TEXT,
    "oauthScope" TEXT NOT NULL,
    "taskId" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "cloud_agent_bindings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "cloud_agent_bindings_agentId_key" ON "cloud_agent_bindings"("agentId");

-- CreateIndex
CREATE UNIQUE INDEX "cloud_agent_bindings_oauthClientId_key" ON "cloud_agent_bindings"("oauthClientId");

-- CreateIndex
CREATE UNIQUE INDEX "cloud_agent_bindings_oauthScope_key" ON "cloud_agent_bindings"("oauthScope");

-- AddForeignKey
ALTER TABLE "cloud_agent_bindings" ADD CONSTRAINT "cloud_agent_bindings_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

