-- Product improvement data (2 Nov design): per-person and per-workspace switches (default on) and the
-- redacted samples table.
-- Rollback: DROP TABLE "product_samples"; DROP TABLE "user_data_preferences";
-- ALTER TABLE "tenants" DROP COLUMN "dataImproveManar", DROP COLUMN "dataAiTraining";

ALTER TABLE "tenants" ADD COLUMN "dataImproveManar" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN "dataAiTraining" BOOLEAN NOT NULL DEFAULT true;

CREATE TABLE "user_data_preferences" (
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "improveManar" BOOLEAN NOT NULL DEFAULT true,
    "aiTraining" BOOLEAN NOT NULL DEFAULT true,
    "noticeDismissed" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_data_preferences_pkey" PRIMARY KEY ("issuer","subject")
);

CREATE TABLE "product_samples" (
    "id" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "tool" TEXT NOT NULL,
    "decision" TEXT NOT NULL,
    "text" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL,
    "aiTrainingAllowed" BOOLEAN NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "product_samples_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "product_samples_issuer_subject_idx" ON "product_samples"("issuer", "subject");
CREATE INDEX "product_samples_tenantId_idx" ON "product_samples"("tenantId");
CREATE INDEX "product_samples_createdAt_idx" ON "product_samples"("createdAt");
