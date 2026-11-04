-- A re-signup match records the exact fingerprint and the ban it created (security review 4 Nov).
-- Rollback: ALTER TABLE "staff_restriction_matches" DROP COLUMN "valueHash", DROP COLUMN "createdRestrictionId";
ALTER TABLE "staff_restriction_matches" ADD COLUMN "valueHash" TEXT;
ALTER TABLE "staff_restriction_matches" ADD COLUMN "createdRestrictionId" TEXT;
