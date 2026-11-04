-- CreateTable
CREATE TABLE "ent_settings" (
    "id" INTEGER NOT NULL DEFAULT 1,
    "orgNameEn" TEXT NOT NULL,
    "orgNameAr" TEXT NOT NULL,
    "orgShort" TEXT NOT NULL,
    "logo" BYTEA,
    "logoType" TEXT,
    "noticeEn" TEXT,
    "noticeAr" TEXT,
    "noticeVersion" INTEGER NOT NULL DEFAULT 1,
    "dpoContact" TEXT,
    "retentionDays" INTEGER NOT NULL DEFAULT 90,
    "summaryDays" INTEGER NOT NULL DEFAULT 365,
    "pendingRetentionDays" INTEGER,
    "pendingRetentionAt" TIMESTAMP(3),
    "exceptionWindowMinutes" INTEGER NOT NULL DEFAULT 30,
    "workWeek" JSONB NOT NULL,
    "timeZone" TEXT NOT NULL DEFAULT 'Asia/Dubai',
    "defaultLanguage" TEXT NOT NULL DEFAULT 'en',
    "unreadableFile" TEXT NOT NULL DEFAULT 'ASK',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ent_settings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ent_people" (
    "id" TEXT NOT NULL,
    "externalId" TEXT,
    "email" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "orgUnitId" TEXT,
    "managerId" TEXT,
    "preferredLanguage" TEXT,
    "accountEnabled" BOOLEAN NOT NULL DEFAULT true,
    "noticeSentVersion" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ent_people_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ent_enrol_keys" (
    "id" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "label" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "uses" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ent_enrol_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ent_devices" (
    "id" TEXT NOT NULL,
    "publicKeyJwk" JSONB NOT NULL,
    "keyThumbprint" TEXT NOT NULL,
    "personId" TEXT,
    "identityVerified" BOOLEAN NOT NULL DEFAULT false,
    "profileEmail" TEXT,
    "browser" TEXT NOT NULL,
    "extensionVersion" TEXT NOT NULL,
    "policyVersion" TEXT,
    "configHash" TEXT,
    "lastHeartbeatAt" TIMESTAMP(3),
    "enrolKeyId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ent_devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ent_identity_nonces" (
    "id" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "nonceHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ent_identity_nonces_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ent_events" (
    "id" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "personId" TEXT,
    "clientEventId" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "ruleId" TEXT,
    "trace" JSONB NOT NULL,
    "counts" JSONB NOT NULL,
    "packVersion" TEXT,
    "at" TIMESTAMP(3) NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ent_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ent_tamper_signals" (
    "id" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "openedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "closedAt" TIMESTAMP(3),

    CONSTRAINT "ent_tamper_signals_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ent_site_visits" (
    "deviceId" TEXT NOT NULL,
    "day" TEXT NOT NULL,
    "host" TEXT NOT NULL,
    "count" INTEGER NOT NULL,

    CONSTRAINT "ent_site_visits_pkey" PRIMARY KEY ("deviceId","day","host")
);

-- CreateIndex
CREATE UNIQUE INDEX "ent_people_externalId_key" ON "ent_people"("externalId");

-- CreateIndex
CREATE UNIQUE INDEX "ent_people_email_key" ON "ent_people"("email");

-- CreateIndex
CREATE INDEX "ent_people_managerId_idx" ON "ent_people"("managerId");

-- CreateIndex
CREATE INDEX "ent_people_orgUnitId_idx" ON "ent_people"("orgUnitId");

-- CreateIndex
CREATE UNIQUE INDEX "ent_enrol_keys_keyHash_key" ON "ent_enrol_keys"("keyHash");

-- CreateIndex
CREATE UNIQUE INDEX "ent_devices_keyThumbprint_key" ON "ent_devices"("keyThumbprint");

-- CreateIndex
CREATE INDEX "ent_devices_personId_idx" ON "ent_devices"("personId");

-- CreateIndex
CREATE UNIQUE INDEX "ent_identity_nonces_nonceHash_key" ON "ent_identity_nonces"("nonceHash");

-- CreateIndex
CREATE INDEX "ent_identity_nonces_deviceId_idx" ON "ent_identity_nonces"("deviceId");

-- CreateIndex
CREATE INDEX "ent_events_receivedAt_idx" ON "ent_events"("receivedAt");

-- CreateIndex
CREATE INDEX "ent_events_personId_receivedAt_idx" ON "ent_events"("personId", "receivedAt");

-- CreateIndex
CREATE INDEX "ent_events_ruleId_receivedAt_idx" ON "ent_events"("ruleId", "receivedAt");

-- CreateIndex
CREATE UNIQUE INDEX "ent_events_deviceId_clientEventId_key" ON "ent_events"("deviceId", "clientEventId");

-- CreateIndex
CREATE INDEX "ent_tamper_signals_deviceId_closedAt_idx" ON "ent_tamper_signals"("deviceId", "closedAt");

-- AddForeignKey
ALTER TABLE "ent_people" ADD CONSTRAINT "ent_people_managerId_fkey" FOREIGN KEY ("managerId") REFERENCES "ent_people"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ent_devices" ADD CONSTRAINT "ent_devices_personId_fkey" FOREIGN KEY ("personId") REFERENCES "ent_people"("id") ON DELETE SET NULL ON UPDATE CASCADE;

