-- ADR-0009 (watcher): agent quarantine.
--
-- Additive: one table with a unique index and a foreign key. (The built-in
-- Manar connector is an ordinary tools row; no enum change, so API processes
-- on the previous client keep reading tools.)
--
-- Rollback (after rolling back the code that reads it; dropping the table
-- discards the current quarantine state, history stays in the audit chain):
--   DROP TABLE "agent_quarantines";

-- CreateTable
CREATE TABLE "agent_quarantines" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL,
    "reason" TEXT NOT NULL,
    "detector" TEXT,
    "evidence" JSONB NOT NULL DEFAULT '[]',
    "explanationEn" TEXT,
    "explanationAr" TEXT,
    "quarantinedByAgentId" TEXT NOT NULL,
    "decisionId" TEXT,
    "quarantinedAt" TIMESTAMP(3) NOT NULL,
    "releasedBy" TEXT,
    "releasedAt" TIMESTAMP(3),
    "releaseNote" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agent_quarantines_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "agent_quarantines_agentId_key" ON "agent_quarantines"("agentId");

-- AddForeignKey
ALTER TABLE "agent_quarantines" ADD CONSTRAINT "agent_quarantines_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

