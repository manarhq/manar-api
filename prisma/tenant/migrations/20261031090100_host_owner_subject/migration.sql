-- Who enrolled a host: the Keycloak subject of the install key's creator (HostAuthGuard exposes it
-- as req.host.ownerSubject). Additive: one nullable column.
--
-- Rollback (after rolling back the code that reads it): ALTER TABLE "hosts" DROP COLUMN "ownerSubject";

-- AlterTable
ALTER TABLE "hosts" ADD COLUMN     "ownerSubject" TEXT;
