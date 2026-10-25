-- docs/edge.md: per-agent egress allow-list for the Manar edge proxy.
--
-- Additive: two tables (allow-list rules; gateway event batches already recorded, for retries).
--
-- Rollback (after rolling back the code that reads it; the allow-lists are lost, their history
-- stays in the audit chain as agent.egress_rule.added/removed):
--   DROP TABLE "agent_egress_rules"; DROP TABLE "edge_event_batches";

-- CreateTable
CREATE TABLE "agent_egress_rules" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "reason" TEXT,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "agent_egress_rules_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "agent_egress_rules_agentId_host_key" ON "agent_egress_rules"("agentId", "host");

-- AddForeignKey
ALTER TABLE "agent_egress_rules" ADD CONSTRAINT "agent_egress_rules_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- CreateTable
CREATE TABLE "edge_event_batches" (
    "batchId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "edge_event_batches_pkey" PRIMARY KEY ("batchId")
);

-- CreateIndex
CREATE INDEX "edge_event_batches_createdAt_idx" ON "edge_event_batches"("createdAt");
