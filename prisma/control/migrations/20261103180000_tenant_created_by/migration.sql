-- Who asked for each workspace, kept when ownership moves: per-person creation limits count by it.
-- Rollback: DROP INDEX "tenants_createdByIssuer_createdBySubject_kind_idx";
--           ALTER TABLE "tenants" DROP COLUMN "createdByIssuer", DROP COLUMN "createdBySubject";
ALTER TABLE "tenants" ADD COLUMN "createdByIssuer" TEXT;
ALTER TABLE "tenants" ADD COLUMN "createdBySubject" TEXT;

CREATE INDEX "tenants_createdByIssuer_createdBySubject_kind_idx" ON "tenants"("createdByIssuer", "createdBySubject", "kind");

-- Existing workspaces: the owner Membership that workspace creation wrote in the same transaction.
UPDATE "tenants" t
SET "createdByIssuer" = m."issuer", "createdBySubject" = m."subject"
FROM "memberships" m
WHERE m."tenantId" = t."id"
  AND m."grantedBy" = 'system:workspace-create'
  AND t."createdBySubject" IS NULL;
