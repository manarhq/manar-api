-- DESK Phase 1: account index, staff RBAC, staff audit chain, restrictions, appeals, error references.
-- Additive only: no existing table or column changes.
-- Rollback: DROP TABLE of every table created below (all are new) and DROP TYPE of the new enums;
--           pg_trgm stays (harmless, other tables may use it later).
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- CreateEnum
CREATE TYPE "StaffTeam" AS ENUM ('DEV', 'SALES', 'PARTNERSHIPS', 'SUPPORT', 'BILLING', 'TRUST_SAFETY', 'LEADERSHIP');

-- CreateEnum
CREATE TYPE "StaffStatus" AS ENUM ('INVITED', 'ACTIVE', 'DISABLED');

-- CreateEnum
CREATE TYPE "StaffPrincipalType" AS ENUM ('STAFF', 'GROUP');

-- CreateEnum
CREATE TYPE "StaffAssignmentKind" AS ENUM ('ACTIVE', 'ELIGIBLE');

-- CreateEnum
CREATE TYPE "StaffChangeStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED', 'EXPIRED', 'EXECUTED', 'FAILED');

-- CreateEnum
CREATE TYPE "StaffRestrictionKind" AS ENUM ('WARNING', 'SUSPEND', 'BAN');

-- CreateEnum
CREATE TYPE "StaffFingerprintKind" AS ENUM ('EMAIL', 'IDP_EMAIL', 'IDP_IDENTITY', 'CARD', 'DEVICE', 'TPM_EK', 'ENTRA_TID');

-- CreateEnum
CREATE TYPE "StaffAppealStatus" AS ENUM ('OPEN', 'UPHELD', 'OVERTURNED');

-- CreateTable
CREATE TABLE "accounts" (
    "id" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "displayName" TEXT NOT NULL DEFAULT '',
    "normalizedEmail" TEXT,
    "emailVerified" BOOLEAN NOT NULL DEFAULT false,
    "idp" TEXT,
    "idpUserHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastCountry" TEXT,
    "riskScore" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_device_index" (
    "tenantId" TEXT NOT NULL,
    "hostId" TEXT NOT NULL,
    "machineId" TEXT NOT NULL,
    "deviceHash" TEXT,
    "ekHash" TEXT,
    "hostname" TEXT,
    "os" TEXT,
    "status" TEXT NOT NULL,
    "ownerIssuer" TEXT,
    "ownerSubject" TEXT,
    "lastSeenAt" TIMESTAMP(3),
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "staff_device_index_pkey" PRIMARY KEY ("tenantId","hostId")
);

-- CreateTable
CREATE TABLE "staff_members" (
    "id" TEXT NOT NULL,
    "issuer" TEXT,
    "subject" TEXT,
    "entraOid" TEXT,
    "email" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "title" TEXT NOT NULL DEFAULT '',
    "team" "StaffTeam" NOT NULL,
    "status" "StaffStatus" NOT NULL DEFAULT 'INVITED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "boundAt" TIMESTAMP(3),

    CONSTRAINT "staff_members_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_roles" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "builtIn" BOOLEAN NOT NULL DEFAULT false,
    "currentVersion" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "archivedAt" TIMESTAMP(3),

    CONSTRAINT "staff_roles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_role_versions" (
    "id" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "permissions" TEXT[],
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "staff_role_versions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_role_assignments" (
    "id" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "principalType" "StaffPrincipalType" NOT NULL,
    "principalId" TEXT NOT NULL,
    "scopeType" TEXT NOT NULL DEFAULT 'PLATFORM',
    "scopeId" TEXT NOT NULL DEFAULT 'manar',
    "kind" "StaffAssignmentKind" NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "grantedBy" TEXT NOT NULL,
    "changeRequestId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),
    "revokedBy" TEXT,

    CONSTRAINT "staff_role_assignments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_groups" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "createdBy" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "staff_groups_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_group_members" (
    "groupId" TEXT NOT NULL,
    "staffId" TEXT NOT NULL,
    "addedBy" TEXT NOT NULL,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "staff_group_members_pkey" PRIMARY KEY ("groupId","staffId")
);

-- CreateTable
CREATE TABLE "staff_elevations" (
    "id" TEXT NOT NULL,
    "staffId" TEXT NOT NULL,
    "assignmentId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "endedAt" TIMESTAMP(3),
    "endedBy" TEXT,

    CONSTRAINT "staff_elevations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_reveals" (
    "id" TEXT NOT NULL,
    "staffId" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "staff_reveals_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_change_requests" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "kind" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "reason" TEXT NOT NULL,
    "proposedBy" TEXT NOT NULL,
    "status" "StaffChangeStatus" NOT NULL DEFAULT 'PENDING',
    "decidedBy" TEXT,
    "decidedAt" TIMESTAMP(3),
    "decisionNote" TEXT,
    "outcome" JSONB,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "staff_change_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_audit_events" (
    "seq" BIGINT NOT NULL,
    "id" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "staffId" TEXT,
    "action" TEXT NOT NULL,
    "targetType" TEXT,
    "targetId" TEXT,
    "data" JSONB NOT NULL,
    "ip" TEXT,
    "requestId" TEXT,
    "previousHash" TEXT,
    "hash" TEXT NOT NULL,

    CONSTRAINT "staff_audit_events_pkey" PRIMARY KEY ("seq")
);

-- CreateTable
CREATE TABLE "staff_restrictions" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "accountId" TEXT,
    "tenantId" TEXT,
    "kind" "StaffRestrictionKind" NOT NULL,
    "category" TEXT NOT NULL,
    "internalNote" TEXT NOT NULL,
    "startsAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "until" TIMESTAMP(3),
    "createdBy" TEXT NOT NULL,
    "changeRequestId" TEXT,
    "liftedAt" TIMESTAMP(3),
    "liftedBy" TEXT,
    "liftReason" TEXT,
    "effects" JSONB,

    CONSTRAINT "staff_restrictions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_restriction_fingerprints" (
    "id" TEXT NOT NULL,
    "restrictionId" TEXT NOT NULL,
    "kind" "StaffFingerprintKind" NOT NULL,
    "valueHash" TEXT NOT NULL,

    CONSTRAINT "staff_restriction_fingerprints_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_restriction_matches" (
    "id" TEXT NOT NULL,
    "kind" "StaffFingerprintKind" NOT NULL,
    "matchedRestrictionId" TEXT NOT NULL,
    "newAccountId" TEXT,
    "newTenantId" TEXT,
    "action" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedBy" TEXT,
    "resolvedAt" TIMESTAMP(3),
    "resolution" TEXT,

    CONSTRAINT "staff_restriction_matches_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_appeals" (
    "id" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "restrictionId" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "text" TEXT NOT NULL,
    "submittedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "dueAt" TIMESTAMP(3) NOT NULL,
    "status" "StaffAppealStatus" NOT NULL DEFAULT 'OPEN',
    "decidedBy" TEXT,
    "decidedAt" TIMESTAMP(3),
    "internalNote" TEXT,

    CONSTRAINT "staff_appeals_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_owner_handovers" (
    "id" TEXT NOT NULL,
    "restrictionId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "candidateMembershipId" TEXT,
    "dueAt" TIMESTAMP(3) NOT NULL,
    "doneAt" TIMESTAMP(3),
    "outcome" TEXT,

    CONSTRAINT "staff_owner_handovers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_notes" (
    "id" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "authorId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "deletedAt" TIMESTAMP(3),

    CONSTRAINT "staff_notes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "staff_tags" (
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "tag" TEXT NOT NULL,
    "addedBy" TEXT NOT NULL,
    "addedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "staff_tags_pkey" PRIMARY KEY ("targetType","targetId","tag")
);

-- CreateTable
CREATE TABLE "staff_error_references" (
    "reference" TEXT NOT NULL,
    "at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "correlationId" TEXT,
    "issuer" TEXT,
    "subject" TEXT,
    "tenantId" TEXT,
    "route" TEXT NOT NULL,
    "status" INTEGER NOT NULL,
    "code" TEXT,

    CONSTRAINT "staff_error_references_pkey" PRIMARY KEY ("reference")
);

-- CreateIndex
CREATE INDEX "accounts_createdAt_id_idx" ON "accounts"("createdAt", "id");

-- CreateIndex
CREATE UNIQUE INDEX "accounts_issuer_subject_key" ON "accounts"("issuer", "subject");

-- CreateIndex
CREATE INDEX "staff_device_index_ownerIssuer_ownerSubject_idx" ON "staff_device_index"("ownerIssuer", "ownerSubject");

-- CreateIndex
CREATE INDEX "staff_device_index_deviceHash_idx" ON "staff_device_index"("deviceHash");

-- CreateIndex
CREATE UNIQUE INDEX "staff_members_entraOid_key" ON "staff_members"("entraOid");

-- CreateIndex
CREATE UNIQUE INDEX "staff_members_email_key" ON "staff_members"("email");

-- CreateIndex
CREATE UNIQUE INDEX "staff_roles_key_key" ON "staff_roles"("key");

-- CreateIndex
CREATE UNIQUE INDEX "staff_role_versions_roleId_version_key" ON "staff_role_versions"("roleId", "version");

-- CreateIndex
CREATE INDEX "staff_role_assignments_principalType_principalId_idx" ON "staff_role_assignments"("principalType", "principalId");

-- CreateIndex
CREATE UNIQUE INDEX "staff_groups_name_key" ON "staff_groups"("name");

-- CreateIndex
CREATE INDEX "staff_elevations_staffId_expiresAt_idx" ON "staff_elevations"("staffId", "expiresAt");

-- CreateIndex
CREATE INDEX "staff_reveals_staffId_targetType_targetId_expiresAt_idx" ON "staff_reveals"("staffId", "targetType", "targetId", "expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "staff_change_requests_code_key" ON "staff_change_requests"("code");

-- CreateIndex
CREATE INDEX "staff_change_requests_status_expiresAt_idx" ON "staff_change_requests"("status", "expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "staff_audit_events_id_key" ON "staff_audit_events"("id");

-- CreateIndex
CREATE INDEX "staff_audit_events_staffId_at_idx" ON "staff_audit_events"("staffId", "at");

-- CreateIndex
CREATE INDEX "staff_audit_events_targetId_at_idx" ON "staff_audit_events"("targetId", "at");

-- CreateIndex
CREATE UNIQUE INDEX "staff_restrictions_code_key" ON "staff_restrictions"("code");

-- CreateIndex
CREATE INDEX "staff_restrictions_accountId_liftedAt_idx" ON "staff_restrictions"("accountId", "liftedAt");

-- CreateIndex
CREATE INDEX "staff_restrictions_tenantId_liftedAt_idx" ON "staff_restrictions"("tenantId", "liftedAt");

-- CreateIndex
CREATE INDEX "staff_restriction_fingerprints_kind_valueHash_idx" ON "staff_restriction_fingerprints"("kind", "valueHash");

-- CreateIndex
CREATE UNIQUE INDEX "staff_restriction_fingerprints_restrictionId_kind_valueHash_key" ON "staff_restriction_fingerprints"("restrictionId", "kind", "valueHash");

-- CreateIndex
CREATE INDEX "staff_restriction_matches_at_idx" ON "staff_restriction_matches"("at");

-- CreateIndex
CREATE UNIQUE INDEX "staff_appeals_code_key" ON "staff_appeals"("code");

-- CreateIndex
CREATE INDEX "staff_appeals_accountId_submittedAt_idx" ON "staff_appeals"("accountId", "submittedAt");

-- CreateIndex
CREATE INDEX "staff_appeals_status_dueAt_idx" ON "staff_appeals"("status", "dueAt");

-- CreateIndex
CREATE INDEX "staff_owner_handovers_doneAt_dueAt_idx" ON "staff_owner_handovers"("doneAt", "dueAt");

-- CreateIndex
CREATE INDEX "staff_notes_targetType_targetId_createdAt_idx" ON "staff_notes"("targetType", "targetId", "createdAt");

-- CreateIndex
CREATE INDEX "staff_tags_tag_idx" ON "staff_tags"("tag");

-- CreateIndex
CREATE INDEX "staff_error_references_at_idx" ON "staff_error_references"("at");

-- AddForeignKey
ALTER TABLE "staff_role_versions" ADD CONSTRAINT "staff_role_versions_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "staff_roles"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "staff_role_assignments" ADD CONSTRAINT "staff_role_assignments_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "staff_roles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "staff_group_members" ADD CONSTRAINT "staff_group_members_groupId_fkey" FOREIGN KEY ("groupId") REFERENCES "staff_groups"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "staff_restrictions" ADD CONSTRAINT "staff_restrictions_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "accounts"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "staff_restriction_fingerprints" ADD CONSTRAINT "staff_restriction_fingerprints_restrictionId_fkey" FOREIGN KEY ("restrictionId") REFERENCES "staff_restrictions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "staff_appeals" ADD CONSTRAINT "staff_appeals_restrictionId_fkey" FOREIGN KEY ("restrictionId") REFERENCES "staff_restrictions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- One open two-person request per (kind, target) (spec §11.3).
CREATE UNIQUE INDEX "staff_change_requests_open_kind_target_key"
  ON "staff_change_requests" ("kind", "targetId") WHERE "status" = 'PENDING';

-- At most one live elevation per staff member (spec §11.1).
CREATE UNIQUE INDEX "staff_elevations_one_open_key"
  ON "staff_elevations" ("staffId") WHERE "endedAt" IS NULL;

-- Search (spec §7.4, AC-3, AC-10): trigram indexes on the text columns staff search.
CREATE INDEX "accounts_displayName_trgm" ON "accounts" USING GIN ("displayName" gin_trgm_ops);
CREATE INDEX "accounts_normalizedEmail_trgm" ON "accounts" USING GIN ("normalizedEmail" gin_trgm_ops);
CREATE INDEX "accounts_normalizedEmail_idx" ON "accounts" ("normalizedEmail");
CREATE INDEX "tenants_name_trgm" ON "tenants" USING GIN ("name" gin_trgm_ops);
CREATE INDEX "tenants_slug_trgm" ON "tenants" USING GIN ("slug" gin_trgm_ops);
CREATE INDEX "staff_device_index_hostname_trgm" ON "staff_device_index" USING GIN ("hostname" gin_trgm_ops);
