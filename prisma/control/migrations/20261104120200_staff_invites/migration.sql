-- Staff invites bind by a one-time token or a pre-recorded Entra object id, never by email.
-- Rollback: DROP INDEX "staff_members_inviteTokenHash_key";
--           ALTER TABLE "staff_members" DROP COLUMN "inviteTokenHash", DROP COLUMN "inviteExpiresAt";
ALTER TABLE "staff_members" ADD COLUMN "inviteTokenHash" TEXT;
ALTER TABLE "staff_members" ADD COLUMN "inviteExpiresAt" TIMESTAMP(3);
CREATE UNIQUE INDEX "staff_members_inviteTokenHash_key" ON "staff_members"("inviteTokenHash");
