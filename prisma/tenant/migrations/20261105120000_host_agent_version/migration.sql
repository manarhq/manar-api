-- AlterTable
ALTER TABLE "hosts" ADD COLUMN     "agentVersion" TEXT,
ADD COLUMN     "agentOs" TEXT,
ADD COLUMN     "agentArch" TEXT,
ADD COLUMN     "agentVersionSeenAt" TIMESTAMP(3);
