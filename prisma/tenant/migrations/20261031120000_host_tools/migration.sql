-- AI tools found on each device, and the owner's protection choice. Additive: one new table.
--
-- Rollback (after rolling back the code that uses it): DROP TABLE "host_tools";

-- CreateTable
CREATE TABLE "host_tools" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "toolId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "version" TEXT,
    "path" TEXT,
    "protected" BOOLEAN NOT NULL DEFAULT false,
    "protectMode" TEXT NOT NULL DEFAULT 'none',
    "desiredProtection" BOOLEAN NOT NULL DEFAULT true,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "host_tools_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "host_tools_toolId_idx" ON "host_tools"("toolId");

-- CreateIndex
CREATE UNIQUE INDEX "host_tools_hostId_toolId_key" ON "host_tools"("hostId", "toolId");

-- AddForeignKey
ALTER TABLE "host_tools" ADD CONSTRAINT "host_tools_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
