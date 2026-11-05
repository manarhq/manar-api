-- AI defaults ON for new Free, Pro and Company workspaces (opt-out), OFF for Government and
-- air-gapped ones, which provisioning sets explicitly (founder, 5 Nov 2026).
-- No existing row is touched here: the `ai:default-on` command flips existing workspaces, keeping
-- every owner's own choice (it reads each workspace's audit log, which this migration cannot).
ALTER TABLE "tenants" ADD COLUMN "allowExternalAiChosen" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "tenants" ADD COLUMN "aiDefaultNoticePending" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "tenants" ALTER COLUMN "allowExternalAi" SET DEFAULT true;
