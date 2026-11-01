-- Phone track: single-use nonces of push action tokens. Additive: one table.
--
-- Rollback (after rolling back the code): DROP TABLE "phone_action_uses";

-- CreateTable
CREATE TABLE "phone_action_uses" (
    "nonce" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "phone_action_uses_pkey" PRIMARY KEY ("nonce")
);

-- CreateIndex
CREATE INDEX "phone_action_uses_expiresAt_idx" ON "phone_action_uses"("expiresAt");
