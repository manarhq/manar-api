-- MCP servers configured in the AI tools of each device (insight track). Additive: one new table.
--
-- Rollback (after rolling back the code that uses it): DROP TABLE "host_mcp_servers";

-- CreateTable
CREATE TABLE "host_mcp_servers" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "toolId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "transport" TEXT NOT NULL,
    "command" TEXT,
    "argCount" INTEGER NOT NULL DEFAULT 0,
    "outsideHome" BOOLEAN NOT NULL DEFAULT false,
    "url" TEXT,
    "pkg" TEXT,
    "pkgVersion" TEXT,
    "envKeys" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "host_mcp_servers_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "host_mcp_servers_toolId_idx" ON "host_mcp_servers"("toolId");

-- CreateIndex
CREATE UNIQUE INDEX "host_mcp_servers_hostId_toolId_name_key" ON "host_mcp_servers"("hostId", "toolId", "name");

-- AddForeignKey
ALTER TABLE "host_mcp_servers" ADD CONSTRAINT "host_mcp_servers_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
