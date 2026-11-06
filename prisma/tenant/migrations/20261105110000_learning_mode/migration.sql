-- Learning mode for new devices (5 Nov 2026, decision 36). Additive.
-- Rollback (after rolling back the code): drop the table and the two columns.
ALTER TABLE "hosts"
  ADD COLUMN "learningStartedAt" TIMESTAMP(3),
  ADD COLUMN "learningOff" BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE "learning_observations" (
  "id" TEXT NOT NULL,
  "hostId" TEXT NOT NULL,
  "toolId" TEXT NOT NULL,
  "actionId" TEXT NOT NULL,
  "scope" TEXT NOT NULL,
  "count" INTEGER NOT NULL DEFAULT 1,
  "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "state" TEXT NOT NULL DEFAULT 'NEW',
  "decidedAt" TIMESTAMP(3),
  CONSTRAINT "learning_observations_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "learning_observations_hostId_toolId_actionId_scope_key"
  ON "learning_observations"("hostId", "toolId", "actionId", "scope");
CREATE INDEX "learning_observations_state_count_idx" ON "learning_observations"("state", "count");
ALTER TABLE "learning_observations"
  ADD CONSTRAINT "learning_observations_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;
