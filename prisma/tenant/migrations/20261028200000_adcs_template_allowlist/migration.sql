-- Certificate template allow-list for key-less enrolment (R2 F2b review). Additive: one column,
-- default empty (no certificate is accepted until a tenant lists its machine templates).
--
-- Rollback: ALTER TABLE "adcs_settings" DROP COLUMN "allowedTemplateOids";

-- AlterTable
ALTER TABLE "adcs_settings" ADD COLUMN     "allowedTemplateOids" TEXT[] DEFAULT ARRAY[]::TEXT[];
