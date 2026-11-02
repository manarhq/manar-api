-- "Admins only" approvals (3 Nov 2026): when true, a device owner can no longer decide their own
-- device's or agent's approvals; only approver roles can. Company workspaces only.
-- Rollback: ALTER TABLE "tenants" DROP COLUMN "approvalsAdminsOnly";
ALTER TABLE "tenants" ADD COLUMN "approvalsAdminsOnly" BOOLEAN NOT NULL DEFAULT false;
