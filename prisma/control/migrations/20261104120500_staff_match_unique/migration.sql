-- One match row per (signal, value, matched restriction, workspace): concurrent enrolments cannot
-- double-count a match or its risk-score effect (security review 4 Nov).
-- Rollback: DROP INDEX "staff_restriction_matches_once_key";
CREATE UNIQUE INDEX "staff_restriction_matches_once_key"
  ON "staff_restriction_matches" ("kind", "valueHash", "matchedRestrictionId", "newTenantId")
  WHERE "newTenantId" IS NOT NULL;
