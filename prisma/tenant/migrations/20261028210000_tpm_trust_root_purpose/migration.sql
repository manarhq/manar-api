-- Separate TPM trust roots for EK certificates from those for vendor AK certificates (Azure vTPM).
-- Additive: one column; existing rows become 'EK', so nothing changes for current tenants.
--
-- Rollback (only after no AK roots are needed; AK-purpose rows would become EK roots, so delete
-- them first): DELETE FROM "tpm_trust_roots" WHERE "purpose" = 'AK';
--   ALTER TABLE "tpm_trust_roots" DROP CONSTRAINT "tpm_trust_roots_purpose_check";
--   ALTER TABLE "tpm_trust_roots" DROP COLUMN "purpose";

-- AlterTable
ALTER TABLE "tpm_trust_roots" ADD COLUMN     "purpose" TEXT NOT NULL DEFAULT 'EK';
ALTER TABLE "tpm_trust_roots" ADD CONSTRAINT "tpm_trust_roots_purpose_check" CHECK ("purpose" IN ('EK', 'AK'));
