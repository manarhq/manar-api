-- A scoped grant answers one ask (5 Nov 2026, security review). Additive.
-- Rollback (after rolling back the code): drop the two columns.
ALTER TABLE "approval_allow_grants" ADD COLUMN "askKey" TEXT;
ALTER TABLE "host_approvals" ADD COLUMN "askKey" TEXT;
