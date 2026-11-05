-- Friction metrics (5 Nov 2026, decision 38): daily rollups per device owner. Additive.
-- Rollback (after rolling back the code): drop the table.
CREATE TABLE "friction_daily" (
  "id" TEXT NOT NULL,
  "day" DATE NOT NULL,
  "subject" TEXT NOT NULL,
  "prompts" INTEGER NOT NULL DEFAULT 0,
  "approvals" INTEGER NOT NULL DEFAULT 0,
  "denies" INTEGER NOT NULL DEFAULT 0,
  "expired" INTEGER NOT NULL DEFAULT 0,
  "deniedLaterApproved" INTEGER NOT NULL DEFAULT 0,
  "answered" INTEGER NOT NULL DEFAULT 0,
  "answerMs" INTEGER NOT NULL DEFAULT 0,
  "blockedMs" INTEGER NOT NULL DEFAULT 0,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "friction_daily_pkey" PRIMARY KEY ("id")
);
CREATE UNIQUE INDEX "friction_daily_day_subject_key" ON "friction_daily"("day", "subject");
