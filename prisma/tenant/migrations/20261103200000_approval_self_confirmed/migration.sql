-- A personal workspace's owner approving their own sensitive request after a fresh sign-in
-- (3 Nov 2026): when that re-confirmation happened. Additive, nullable.
-- Rollback: drop the two columns.
ALTER TABLE "approval_requests" ADD COLUMN "selfConfirmedAt" TIMESTAMP(3);
ALTER TABLE "host_approvals" ADD COLUMN "selfConfirmedAt" TIMESTAMP(3);
