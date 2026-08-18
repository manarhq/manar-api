-- CreateEnum
CREATE TYPE "TaskStatus" AS ENUM ('PENDING', 'ACTIVE', 'EXPIRED', 'REVOKED', 'COMPLETED');

-- CreateTable
CREATE TABLE "tasks" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "requesterId" TEXT NOT NULL,
    "assignedAgentId" TEXT NOT NULL,
    "parentTaskId" TEXT,
    "allowedToolActions" JSONB NOT NULL DEFAULT '[]',
    "allowedResourceSelectors" JSONB NOT NULL DEFAULT '[]',
    "forbiddenActions" JSONB NOT NULL DEFAULT '[]',
    "status" "TaskStatus" NOT NULL DEFAULT 'ACTIVE',
    "startsAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "maxExecutions" INTEGER,
    "executionCount" INTEGER NOT NULL DEFAULT 0,
    "riskCeiling" INTEGER NOT NULL DEFAULT 20,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "tasks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "task_delegations" (
    "id" TEXT NOT NULL,
    "parentTaskId" TEXT NOT NULL,
    "childTaskId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "task_delegations_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "task_delegations_childTaskId_key" ON "task_delegations"("childTaskId");

-- AddForeignKey
ALTER TABLE "tasks" ADD CONSTRAINT "tasks_requesterId_fkey" FOREIGN KEY ("requesterId") REFERENCES "user_profiles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tasks" ADD CONSTRAINT "tasks_assignedAgentId_fkey" FOREIGN KEY ("assignedAgentId") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tasks" ADD CONSTRAINT "tasks_parentTaskId_fkey" FOREIGN KEY ("parentTaskId") REFERENCES "tasks"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "task_delegations" ADD CONSTRAINT "task_delegations_parentTaskId_fkey" FOREIGN KEY ("parentTaskId") REFERENCES "tasks"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "task_delegations" ADD CONSTRAINT "task_delegations_childTaskId_fkey" FOREIGN KEY ("childTaskId") REFERENCES "tasks"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
