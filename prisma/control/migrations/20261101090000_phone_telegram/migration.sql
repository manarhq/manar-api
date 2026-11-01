-- Phone track: Telegram links, link codes, approval messages, and single-use push action nonces.
-- Additive: four tables.
--
-- Rollback (after rolling back the code):
--   DROP TABLE "telegram_links", "telegram_link_codes", "telegram_approval_messages", "phone_action_uses";

-- CreateTable
CREATE TABLE "telegram_links" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "chatId" TEXT NOT NULL,
    "locale" TEXT NOT NULL DEFAULT 'en',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "telegram_links_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "telegram_link_codes" (
    "codeHash" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "telegram_link_codes_pkey" PRIMARY KEY ("codeHash")
);

-- CreateTable
CREATE TABLE "telegram_approval_messages" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "approvalId" TEXT NOT NULL,
    "chatId" TEXT NOT NULL,
    "messageId" INTEGER NOT NULL,
    "text" TEXT NOT NULL,
    "closedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "telegram_approval_messages_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "phone_action_uses" (
    "nonce" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "phone_action_uses_pkey" PRIMARY KEY ("nonce")
);

-- CreateIndex
CREATE UNIQUE INDEX "telegram_links_chatId_key" ON "telegram_links"("chatId");

-- CreateIndex
CREATE INDEX "telegram_links_tenantId_subject_idx" ON "telegram_links"("tenantId", "subject");

-- CreateIndex
CREATE INDEX "telegram_link_codes_subject_idx" ON "telegram_link_codes"("subject");

-- CreateIndex
CREATE UNIQUE INDEX "telegram_approval_messages_approvalId_chatId_key" ON "telegram_approval_messages"("approvalId", "chatId");

-- CreateIndex
CREATE INDEX "telegram_approval_messages_closedAt_createdAt_idx" ON "telegram_approval_messages"("closedAt", "createdAt");

-- CreateIndex
CREATE INDEX "phone_action_uses_expiresAt_idx" ON "phone_action_uses"("expiresAt");
