-- AI defaults ON for new Free, Pro and Company workspaces (opt-out), OFF for Government and
-- air-gapped ones, which provisioning sets explicitly (founder, 5 Nov 2026).
-- No existing row is touched here: the `ai:default-on` command flips existing workspaces, keeping
-- every owner's own choice (it reads each workspace's audit log, which this migration cannot).
ALTER TABLE "tenants" ADD COLUMN "allowExternalAiChosen" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "tenants" ADD COLUMN "aiDefaultNoticePending" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "tenants" ADD COLUMN "aiOptInNoticePending" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "tenants" ALTER COLUMN "allowExternalAi" SET DEFAULT true;

-- The sector is recorded on the tenant at every provisioning path. Backfill from what is known;
-- everything else stays NULL (unknown) and `ai:default-on` leaves it alone.
CREATE TYPE "TenantSector" AS ENUM ('COMMERCIAL', 'GOVERNMENT');
ALTER TABLE "tenants" ADD COLUMN "sector" "TenantSector";
UPDATE "tenants" t SET "sector" = 'GOVERNMENT'
  FROM "enterprise_profiles" p WHERE p."tenantId" = t."id" AND p."sector" = 'GOVERNMENT';
UPDATE "tenants" t SET "sector" = 'COMMERCIAL'
  FROM "enterprise_profiles" p WHERE p."tenantId" = t."id" AND p."sector" = 'ENTERPRISE';
UPDATE "tenants" SET "sector" = 'COMMERCIAL' WHERE "sector" IS NULL AND "kind" = 'PERSONAL';
