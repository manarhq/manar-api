-- Secrets track: watcher events, vault state and vault access requests. Additive: three new tables.
--
-- Rollback (after rolling back the code): DROP TABLE "secret_vault_access"; DROP TABLE "secret_vault"; DROP TABLE "secret_events";

-- CreateTable
CREATE TABLE "secret_events" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "toolId" TEXT,
    "process" TEXT,
    "pathClass" TEXT,
    "maskedPath" TEXT,
    "blocked" BOOLEAN NOT NULL DEFAULT false,
    "at" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "secret_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "secret_vault" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "ref" TEXT NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'REQUESTED',
    "requestedBy" TEXT NOT NULL,
    "detail" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "secret_vault_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "secret_vault_access" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "ref" TEXT NOT NULL,
    "program" TEXT NOT NULL,
    "programPath" TEXT NOT NULL DEFAULT '',
    "programSha" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "decidedBy" TEXT,
    "decidedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "secret_vault_access_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "secret_events_hostId_at_idx" ON "secret_events"("hostId", "at");
CREATE INDEX "secret_events_toolId_at_idx" ON "secret_events"("toolId", "at");
CREATE INDEX "secret_events_type_at_idx" ON "secret_events"("type", "at");
CREATE UNIQUE INDEX "secret_vault_hostId_kind_ref_key" ON "secret_vault"("hostId", "kind", "ref");
CREATE INDEX "secret_vault_hostId_state_idx" ON "secret_vault"("hostId", "state");
CREATE INDEX "secret_vault_access_hostId_status_idx" ON "secret_vault_access"("hostId", "status");
CREATE INDEX "secret_vault_access_status_createdAt_idx" ON "secret_vault_access"("status", "createdAt");
