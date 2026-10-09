-- ADR-003 / security finding S1: the durable decision record, committed
-- before any tool is contacted, and the link from each execution back to it.
--
-- Additive: three enums, one table, one nullable column with its index and
-- foreign key. Existing tool_invocations rows keep decisionId NULL.
--
-- Rollback (only before any code that writes decisions is deployed, or after
-- rolling that code back; dropping the table discards decision history):
--   ALTER TABLE "tool_invocations" DROP CONSTRAINT "tool_invocations_decisionId_fkey";
--   DROP INDEX "tool_invocations_decisionId_idx";
--   ALTER TABLE "tool_invocations" DROP COLUMN "decisionId";
--   DROP TABLE "decisions";
--   DROP TYPE "DecisionStage";
--   DROP TYPE "DecisionChannel";
--   DROP TYPE "DecisionOutcome";

-- CreateEnum
CREATE TYPE "DecisionOutcome" AS ENUM ('ALLOW', 'APPROVAL_REQUIRED', 'DENY');

-- CreateEnum
CREATE TYPE "DecisionChannel" AS ENUM ('REST', 'MCP', 'AUTHORIZE');

-- CreateEnum
CREATE TYPE "DecisionStage" AS ENUM ('REQUEST', 'GRANT_REDEMPTION');

-- AlterTable
ALTER TABLE "tool_invocations" ADD COLUMN     "decisionId" TEXT;

-- CreateTable
CREATE TABLE "decisions" (
    "id" TEXT NOT NULL,
    "outcome" "DecisionOutcome" NOT NULL,
    "reasonCodes" TEXT[],
    "policyId" TEXT,
    "policyVersionId" TEXT,
    "riskScore" INTEGER,
    "inputsHash" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "taskId" TEXT NOT NULL,
    "toolId" TEXT NOT NULL,
    "actionId" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "channel" "DecisionChannel" NOT NULL,
    "stage" "DecisionStage" NOT NULL DEFAULT 'REQUEST',
    "grantId" TEXT,
    "correlationId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "decisions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "decisions_taskId_createdAt_idx" ON "decisions"("taskId", "createdAt");

-- CreateIndex
CREATE INDEX "decisions_agentId_createdAt_idx" ON "decisions"("agentId", "createdAt");

-- CreateIndex
CREATE INDEX "decisions_grantId_idx" ON "decisions"("grantId");

-- CreateIndex
CREATE INDEX "tool_invocations_decisionId_idx" ON "tool_invocations"("decisionId");

-- AddForeignKey
ALTER TABLE "tool_invocations" ADD CONSTRAINT "tool_invocations_decisionId_fkey" FOREIGN KEY ("decisionId") REFERENCES "decisions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

