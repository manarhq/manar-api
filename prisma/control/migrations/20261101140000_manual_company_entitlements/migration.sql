-- Existing (pilot and demo) tenants keep the effective plan they had before plans existed.
--
-- Without an entitlement row a tenant reads as Free (3 devices, 10 agents, 30 days of audit), which
-- would cap every workspace that was created before launch. This gives each existing COMPANY
-- tenant that has no row a `company` entitlement with no Stripe ids, flagged `manual` so it is
-- recognisable as hand-granted and is never touched by Stripe events (those find a tenant by its
-- Stripe customer id, which these rows do not have).
--
-- Idempotent: a tenant that already has a row (a company trial or a paid plan) is left alone, and
-- PERSONAL and SAMPLE tenants are not touched (they are Free by design). Run again any time, e.g.
-- after restoring a pilot tenant. Rollback: DELETE FROM "tenant_entitlements" WHERE "manual";
-- ALTER TABLE "tenant_entitlements" DROP COLUMN "manual";

ALTER TABLE "tenant_entitlements" ADD COLUMN "manual" BOOLEAN NOT NULL DEFAULT false;

INSERT INTO "tenant_entitlements" ("tenantId", "plan", "status", "manual", "createdAt", "updatedAt")
SELECT t."id", 'company', 'active', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM "tenants" t
WHERE t."kind" = 'COMPANY'
  AND t."status" <> 'DELETED'
  AND NOT EXISTS (SELECT 1 FROM "tenant_entitlements" e WHERE e."tenantId" = t."id");
