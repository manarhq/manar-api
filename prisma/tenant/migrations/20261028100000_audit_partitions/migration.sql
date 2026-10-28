-- Audit partitions and checkpoints (docs/audit-chain.md, ADR-0014).
--
-- Splits each tenant's single audit hash chain into 64 partitions. Every existing event becomes
-- partition 0 in its original order (partitionSeq = position by "sequence"), so the old chain
-- verifies unchanged as partition 0. The singleton "audit_chain_state" row becomes partition 0's
-- "audit_partition_state" row; the singleton table is then dropped. Adds "audit_checkpoints"
-- (signed Merkle SEALs) and a partition column on retention anchors.
--
-- Rollback (only while every event is still in partition 0, i.e. before the new code has written
-- to any other partition; after that the old single-chain code cannot verify the log):
--   CREATE TABLE "audit_chain_state" ("id" TEXT NOT NULL, "latestEventId" TEXT, "latestEventHash" TEXT,
--     "eventCount" INTEGER NOT NULL DEFAULT 0, "updatedAt" TIMESTAMP(3) NOT NULL,
--     CONSTRAINT "audit_chain_state_pkey" PRIMARY KEY ("id"));
--   INSERT INTO "audit_chain_state" SELECT 'singleton', "latestEventId", "latestEventHash", "eventCount",
--     CURRENT_TIMESTAMP FROM "audit_partition_state" WHERE "partition" = 0;
--   DROP TABLE "audit_checkpoint_ranges"; DROP TABLE "audit_checkpoints"; DROP TABLE "audit_partition_state";
--   ALTER TABLE "audit_chain_anchors" DROP COLUMN "signature", DROP COLUMN "partition";
--   DROP INDEX "audit_events_partition_partitionSeq_key";
--   ALTER TABLE "audit_events" DROP COLUMN "partitionSeq", DROP COLUMN "partition";

-- AlterTable
ALTER TABLE "audit_events" ADD COLUMN "partition" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN "partitionSeq" INTEGER;

UPDATE "audit_events" AS e
SET "partitionSeq" = r.rn::int
FROM (SELECT "id", ROW_NUMBER() OVER (ORDER BY "sequence") AS rn FROM "audit_events") AS r
WHERE e."id" = r."id";

ALTER TABLE "audit_events" ALTER COLUMN "partitionSeq" SET NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "audit_events_partition_partitionSeq_key" ON "audit_events"("partition", "partitionSeq");

-- AlterTable
ALTER TABLE "audit_chain_anchors" ADD COLUMN "partition" INTEGER NOT NULL DEFAULT 0;
-- Existing anchors continue the old chain (partition 0); new ones must name their partition.
ALTER TABLE "audit_chain_anchors" ALTER COLUMN "partition" DROP DEFAULT;
-- New anchors are signed by retention; existing ones stay unsigned (accepted in partition 0 only).
ALTER TABLE "audit_chain_anchors" ADD COLUMN "signature" TEXT;

-- CreateTable
CREATE TABLE "audit_partition_state" (
    "partition" INTEGER NOT NULL,
    "latestEventId" TEXT,
    "latestEventHash" TEXT,
    "latestSeq" INTEGER NOT NULL DEFAULT 0,
    "eventCount" INTEGER NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "audit_partition_state_pkey" PRIMARY KEY ("partition")
);

INSERT INTO "audit_partition_state" ("partition", "latestEventId", "latestEventHash", "latestSeq", "eventCount", "updatedAt")
SELECT 0, s."latestEventId", s."latestEventHash", (SELECT COUNT(*) FROM "audit_events")::int, s."eventCount", CURRENT_TIMESTAMP
FROM "audit_chain_state" AS s
WHERE s."id" = 'singleton';

-- CreateTable
CREATE TABLE "audit_checkpoints" (
    "seq" BIGINT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL,
    "partitionHeads" JSONB NOT NULL,
    "roots" JSONB NOT NULL,
    "previousCheckpointHash" TEXT,
    "checkpointHash" TEXT NOT NULL,
    "signature" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,

    CONSTRAINT "audit_checkpoints_pkey" PRIMARY KEY ("seq")
);

-- CreateIndex
CREATE UNIQUE INDEX "audit_checkpoints_checkpointHash_key" ON "audit_checkpoints"("checkpointHash");

-- CreateTable
CREATE TABLE "audit_checkpoint_ranges" (
    "partition" INTEGER NOT NULL,
    "fromSeq" INTEGER NOT NULL,
    "toSeq" INTEGER NOT NULL,
    "checkpointSeq" BIGINT NOT NULL,
    "root" TEXT NOT NULL,

    CONSTRAINT "audit_checkpoint_ranges_pkey" PRIMARY KEY ("partition","fromSeq")
);

-- CreateIndex
CREATE INDEX "audit_checkpoint_ranges_partition_toSeq_idx" ON "audit_checkpoint_ranges"("partition", "toSeq");

-- DropTable
DROP TABLE "audit_chain_state";
