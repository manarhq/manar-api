-- The device reports its modules (door, jail, warden, ...) with each inventory, so the console's
-- home screen can say "Network control is not running on <device>" like `manar-edge status` does.
-- Additive: one nullable column.
--
-- Rollback (after rolling back the code): ALTER TABLE "hosts" DROP COLUMN "modules";

-- AlterTable
ALTER TABLE "hosts" ADD COLUMN "modules" JSONB;
