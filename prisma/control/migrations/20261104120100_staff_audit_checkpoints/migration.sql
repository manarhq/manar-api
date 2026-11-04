-- Signed checkpoints of the staff audit chain head (DESK Phase 1, security review 4 Nov).
-- Rollback: DROP TABLE "staff_audit_checkpoints";
CREATE TABLE "staff_audit_checkpoints" (
    "seq" BIGINT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "headSeq" BIGINT NOT NULL,
    "headHash" TEXT NOT NULL,
    "previousCheckpointHash" TEXT,
    "checkpointHash" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,

    CONSTRAINT "staff_audit_checkpoints_pkey" PRIMARY KEY ("seq")
);

CREATE UNIQUE INDEX "staff_audit_checkpoints_checkpointHash_key" ON "staff_audit_checkpoints"("checkpointHash");
