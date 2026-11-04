-- Live security fixes, 4 Nov 2026 (edge-case design, section 7).
--
-- 1. A new key for a known machineId becomes its own PENDING host ("possible clone or
--    re-install") instead of replacing the existing host's key. Hosts are no longer unique by
--    machineId; only the original (cloneOfHostId IS NULL) is.
-- 2. Removal reason (moved to another workspace, account deleted) and "unassigned" for company
--    devices whose person deleted their account.
-- 3. Vault "8 hours" and "Always" grants carry an end and can be withdrawn from the console.
-- 4. Install keys no longer live forever: a key with no expiry ends 30 days from now, or 365 days
--    when it is locked to address ranges.
--
-- Rollback (after rolling back the code): the columns can stay. To restore the old uniqueness,
-- first remove or rename clone hosts (cloneOfHostId IS NOT NULL), then
--   DROP INDEX "hosts_machineId_primary_key"; DROP INDEX "hosts_machineId_idx";
--   CREATE UNIQUE INDEX "hosts_machineId_key" ON "hosts"("machineId");
-- The install-key expiry in step 4 cannot be told apart from an expiry an admin set.

ALTER TABLE "hosts" ADD COLUMN "removedReason" TEXT;
ALTER TABLE "hosts" ADD COLUMN "cloneOfHostId" TEXT;
ALTER TABLE "hosts" ADD COLUMN "unassignedAt" TIMESTAMP(3);

DROP INDEX "hosts_machineId_key";
CREATE INDEX "hosts_machineId_idx" ON "hosts"("machineId");
CREATE UNIQUE INDEX "hosts_machineId_primary_key" ON "hosts"("machineId") WHERE "cloneOfHostId" IS NULL;

ALTER TABLE "secret_vault_access" ADD COLUMN "expiresAt" TIMESTAMP(3);
ALTER TABLE "secret_vault_access" ADD COLUMN "withdrawnAt" TIMESTAMP(3);
ALTER TABLE "secret_vault_access" ADD COLUMN "withdrawnBy" TEXT;
UPDATE "secret_vault_access" SET "expiresAt" = "decidedAt" + INTERVAL '8 hours'
  WHERE "status" = 'ALLOW_8H' AND "decidedAt" IS NOT NULL;

UPDATE "install_keys"
  SET "expiresAt" = CURRENT_TIMESTAMP + CASE WHEN cardinality("allowedCidrs") > 0
    THEN INTERVAL '365 days' ELSE INTERVAL '30 days' END
  WHERE "expiresAt" IS NULL AND "revokedAt" IS NULL;
