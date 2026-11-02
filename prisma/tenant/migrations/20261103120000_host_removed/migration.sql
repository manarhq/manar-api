-- "Remove device" keeps the host row (status REMOVED) instead of deleting it, so the device's
-- sessions, approvals and events stay readable. Additive: one enum value, one nullable column.
--
-- Rollback (after rolling back the code): ALTER TABLE "hosts" DROP COLUMN "removedAt";
-- (the enum value can stay; Postgres cannot drop one in place).

-- AlterEnum
ALTER TYPE "HostStatus" ADD VALUE 'REMOVED';

-- AlterTable
ALTER TABLE "hosts" ADD COLUMN "removedAt" TIMESTAMP(3);
