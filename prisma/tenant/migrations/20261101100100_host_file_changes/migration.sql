-- CreateEnum
CREATE TYPE "FileChangeRestore" AS ENUM ('NONE', 'REQUESTED', 'RESTORED', 'FAILED');

-- CreateTable
CREATE TABLE "host_file_changes" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "snapshotId" TEXT NOT NULL,
    "tool" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "existed" BOOLEAN NOT NULL,
    "sizeBytes" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "takenAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "restoreStatus" "FileChangeRestore" NOT NULL DEFAULT 'NONE',
    "restoreRequestedBy" TEXT,
    "restoreRequestedAt" TIMESTAMP(3),
    "restoreDoneAt" TIMESTAMP(3),
    "restoreNote" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "host_file_changes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "host_file_changes_hostId_snapshotId_key" ON "host_file_changes"("hostId", "snapshotId");

-- CreateIndex
CREATE INDEX "host_file_changes_hostId_takenAt_idx" ON "host_file_changes"("hostId", "takenAt");

-- CreateIndex
CREATE INDEX "host_file_changes_hostId_restoreStatus_idx" ON "host_file_changes"("hostId", "restoreStatus");

-- AddForeignKey
ALTER TABLE "host_file_changes" ADD CONSTRAINT "host_file_changes_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
