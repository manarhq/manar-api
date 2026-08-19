-- CreateTable
CREATE TABLE "platform_kill_switches" (
    "id" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT false,
    "reason" TEXT,
    "activatedBy" TEXT,
    "activatedAt" TIMESTAMP(3),
    "deactivatedBy" TEXT,
    "deactivatedAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "platform_kill_switches_pkey" PRIMARY KEY ("id")
);
