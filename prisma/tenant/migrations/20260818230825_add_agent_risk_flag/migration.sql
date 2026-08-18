-- CreateTable
CREATE TABLE "agent_risk_flags" (
    "id" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "agent_risk_flags_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "agent_risk_flags_agentId_expiresAt_idx" ON "agent_risk_flags"("agentId", "expiresAt");

-- AddForeignKey
ALTER TABLE "agent_risk_flags" ADD CONSTRAINT "agent_risk_flags_agentId_fkey" FOREIGN KEY ("agentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
