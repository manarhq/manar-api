-- CreateEnum
CREATE TYPE "KillSwitchScope" AS ENUM ('TENANT', 'AGENT_GROUP', 'AGENT', 'TOOL');

-- CreateTable
CREATE TABLE "kill_switches" (
    "id" TEXT NOT NULL,
    "scope" "KillSwitchScope" NOT NULL,
    "targetId" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "reason" TEXT,
    "activatedBy" TEXT NOT NULL,
    "activatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deactivatedBy" TEXT,
    "deactivatedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "kill_switches_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "kill_switches_scope_targetId_active_idx" ON "kill_switches"("scope", "targetId", "active");

-- AddForeignKey
ALTER TABLE "kill_switches" ADD CONSTRAINT "kill_switches_activatedBy_fkey" FOREIGN KEY ("activatedBy") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "kill_switches" ADD CONSTRAINT "kill_switches_deactivatedBy_fkey" FOREIGN KEY ("deactivatedBy") REFERENCES "user_profiles"("id") ON DELETE SET NULL ON UPDATE CASCADE;
