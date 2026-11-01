ALTER TABLE "launch_offer_claims"
  ADD COLUMN "trialEndsAt" TIMESTAMP(3),
  ADD COLUMN "keptAt" TIMESTAMP(3),
  ADD COLUMN "reminderSentAt" TIMESTAMP(3);
