-- Phase 1 (Gate 0 finding S10): revocation is now local-first. The mTLS guard
-- reads `revokedAt` from PostgreSQL, so that is set before OpenBao is called;
-- an OpenBao outage can no longer leave a revoked agent working. This column
-- records when OpenBao confirmed the revocation, so a failed CA call is visible
-- and retried on the next revoke.
--
-- Every row revoked before this migration went through OpenBao first, so
-- backfilling from `revokedAt` is truthful.
--
-- Rollback: ALTER TABLE "agent_certificates" DROP COLUMN "caRevokedAt";

-- AlterTable
ALTER TABLE "agent_certificates" ADD COLUMN     "caRevokedAt" TIMESTAMP(3);

UPDATE "agent_certificates" SET "caRevokedAt" = "revokedAt" WHERE "revokedAt" IS NOT NULL;
