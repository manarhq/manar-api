-- CreateEnum
CREATE TYPE "TenantStatus" AS ENUM ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'DEPROVISIONING', 'DELETED');

-- CreateEnum
CREATE TYPE "TenantResidency" AS ENUM ('UAE', 'CUSTOM_REGION', 'AIR_GAPPED');

-- CreateEnum
CREATE TYPE "SecretKind" AS ENUM ('DATABASE_CREDENTIAL');

-- CreateEnum
CREATE TYPE "SecretProvider" AS ENUM ('ENV', 'OPENBAO');

-- CreateTable
CREATE TABLE "tenants" (
    "id" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" "TenantStatus" NOT NULL DEFAULT 'PROVISIONING',
    "residency" "TenantResidency" NOT NULL DEFAULT 'UAE',
    "allowExternalAi" BOOLEAN NOT NULL DEFAULT false,
    "allowOutboundTelemetry" BOOLEAN NOT NULL DEFAULT false,
    "allowCloudStorage" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tenants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tenant_database_bindings" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "databaseName" TEXT NOT NULL,
    "secretReferenceId" TEXT NOT NULL,
    "provisioningStatus" "TenantStatus" NOT NULL DEFAULT 'PROVISIONING',
    "provisionedAt" TIMESTAMP(3),
    "lastMigratedAt" TIMESTAMP(3),
    "lastMigrationVersion" TEXT,
    "deploymentMetadata" JSONB,

    CONSTRAINT "tenant_database_bindings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "secret_references" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "kind" "SecretKind" NOT NULL DEFAULT 'DATABASE_CREDENTIAL',
    "provider" "SecretProvider" NOT NULL DEFAULT 'ENV',
    "reference" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "secret_references_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "tenants_slug_key" ON "tenants"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_database_bindings_tenantId_key" ON "tenant_database_bindings"("tenantId");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_database_bindings_databaseName_key" ON "tenant_database_bindings"("databaseName");

-- CreateIndex
CREATE UNIQUE INDEX "tenant_database_bindings_secretReferenceId_key" ON "tenant_database_bindings"("secretReferenceId");

-- AddForeignKey
ALTER TABLE "tenant_database_bindings" ADD CONSTRAINT "tenant_database_bindings_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tenant_database_bindings" ADD CONSTRAINT "tenant_database_bindings_secretReferenceId_fkey" FOREIGN KEY ("secretReferenceId") REFERENCES "secret_references"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "secret_references" ADD CONSTRAINT "secret_references_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
