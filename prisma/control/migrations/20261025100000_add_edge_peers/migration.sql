-- docs/edge.md: the platform registry of edge (WireGuard) peers and the global peer version.
--
-- Additive: one enum, two tables, one singleton row. Nothing reads them unless MANAR_EDGE_ENABLED
-- is set, apart from the refresh hooks, which find no rows.
--
-- Rollback (after rolling back the code that reads them; the gateway then has no peers, so every
-- edge agent loses its tunnel until it re-enrolls on a build with the feature):
--   DROP TABLE "edge_peers"; DROP TABLE "edge_state"; DROP TYPE "EdgePeerState";

-- CreateEnum
CREATE TYPE "EdgePeerState" AS ENUM ('active', 'cut');

-- CreateTable
CREATE TABLE "edge_peers" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "tenantSlug" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "agentSlug" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "state" "EdgePeerState" NOT NULL,
    "cutReason" TEXT,
    "allowHosts" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "version" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "edge_peers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "edge_state" (
    "id" TEXT NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "edge_state_pkey" PRIMARY KEY ("id")
);

-- The singleton every peer change locks and bumps.
INSERT INTO "edge_state" ("id", "version") VALUES ('singleton', 0);

-- CreateIndex
CREATE UNIQUE INDEX "edge_peers_publicKey_key" ON "edge_peers"("publicKey");

-- CreateIndex
CREATE UNIQUE INDEX "edge_peers_address_key" ON "edge_peers"("address");

-- CreateIndex
CREATE INDEX "edge_peers_version_idx" ON "edge_peers"("version");

-- CreateIndex
CREATE UNIQUE INDEX "edge_peers_tenantId_agentId_key" ON "edge_peers"("tenantId", "agentId");

-- AddForeignKey
ALTER TABLE "edge_peers" ADD CONSTRAINT "edge_peers_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;
