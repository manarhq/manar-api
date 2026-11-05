-- Learning mode hardening (5 Nov 2026, security review). Additive except the unique key.
-- Rollback (after rolling back the code): drop the trigger, function and columns; restore the old key.
ALTER TABLE "hosts" ADD COLUMN "firstApprovedAt" TIMESTAMP(3);
UPDATE "hosts" SET "firstApprovedAt" = "approvedAt" WHERE "approvedAt" IS NOT NULL;

-- The first approval is the anchor of the 7 days. A trigger, so no code path (re-approval after a
-- rekey, a revive, a rule) can move it: an update keeps the old value.
CREATE FUNCTION hosts_first_approved() RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    NEW."firstApprovedAt" := COALESCE(OLD."firstApprovedAt", NEW."firstApprovedAt");
  END IF;
  IF NEW."firstApprovedAt" IS NULL AND NEW."approvedAt" IS NOT NULL THEN
    NEW."firstApprovedAt" := NEW."approvedAt";
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER hosts_first_approved BEFORE INSERT OR UPDATE ON "hosts"
  FOR EACH ROW EXECUTE FUNCTION hosts_first_approved();

ALTER TABLE "learning_observations" ADD COLUMN "askKey" TEXT NOT NULL DEFAULT '';
DROP INDEX "learning_observations_hostId_toolId_actionId_scope_key";
CREATE UNIQUE INDEX "learning_observations_hostId_toolId_actionId_scope_askKey_key"
  ON "learning_observations"("hostId", "toolId", "actionId", "scope", "askKey");
