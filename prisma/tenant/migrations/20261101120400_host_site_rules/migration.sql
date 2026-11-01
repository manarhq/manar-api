-- JAIL per-site decisions (wave 2): what a person allowed or blocked for one AI tool on one device.
-- Additive: one table. Rollback (after rolling back the code): DROP TABLE "host_site_rules";

CREATE TABLE "host_site_rules" (
    "id" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "toolId" TEXT NOT NULL,
    "site" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "source" TEXT NOT NULL,
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "host_site_rules_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "host_site_rules_mode_check" CHECK ("mode" IN ('ALLOW', 'DENY'))
);

CREATE UNIQUE INDEX "host_site_rules_hostId_toolId_site_key" ON "host_site_rules"("hostId", "toolId", "site");
CREATE INDEX "host_site_rules_hostId_idx" ON "host_site_rules"("hostId");

ALTER TABLE "host_site_rules" ADD CONSTRAINT "host_site_rules_hostId_fkey" FOREIGN KEY ("hostId") REFERENCES "hosts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
